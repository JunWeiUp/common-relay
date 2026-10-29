import asyncio
import base64
import contextlib
import json
import struct
import uuid
import hashlib
import time
from .journal import Journal
from urllib.parse import urlsplit
from websockets.asyncio.client import connect
from .crypto import EncryptStream, DecryptStream, stream_aad, frame

class RelayError(Exception):
    pass

class Stream:
    def __init__(self, client, peer, object_id, encryptor, decryptor=None):
        self.client, self.peer, self.id = client, peer, object_id
        self.encryptor, self.decryptor = encryptor, decryptor
        self.tx, self.rx = 0, 0
        self.incoming = asyncio.Queue(16)
        self.closed = False
        self.send_lock = asyncio.Lock()
        self.credit = asyncio.Semaphore(8)
        self.acknowledged = 0

    async def send(self, data, final=False):
        async with self.send_lock:
            if self.closed:
                raise RelayError('Closed stream')
            for offset in range(0, max(1, len(data)), 65519):
                await asyncio.wait_for(self.credit.acquire(),30)
                if self.closed:
                    raise RelayError('Closed stream')
                part = data[offset:offset+65519]
                last = final and offset+65519 >= len(data)
                aad = stream_aad(self.client.identity, self.client.identity.device, self.peer, self.id, self.tx)
                payload = self.encryptor.push(part, aad, last)
                await self.client.ws.send(frame(self.id, self.tx, payload))
                self.tx += 1

    async def receive(self):
        item = await self.incoming.get()
        if isinstance(item, Exception):
            raise item
        seq, cipher = item
        if seq != self.rx or self.decryptor is None:
            raise RelayError('Invalid stream sequence or state')
        aad = stream_aad(self.client.identity, self.peer, self.client.identity.device, self.id, self.rx)
        plain = self.decryptor.pull(cipher, aad)
        self.rx += 1
        await self.client.send_event({'type':'stream.credit','id':self.id,'sequence':self.rx})
        return plain

    async def close(self):
        was_closed = self.closed
        self.abort()
        self.client.streams.pop(self.id, None)
        if not was_closed:
            await self.client.send_event({'type': 'stream.close', 'id': self.id})

    def abort(self):
        if self.closed: return
        self.closed = True
        for _ in range(8):
            self.credit.release()
        while not self.incoming.empty():
            self.incoming.get_nowait()
        self.incoming.put_nowait(RelayError('Stream interrupted; do not replay operations'))

class Client:
    def __init__(self, url, token, identity, state_path=None, *, allow_local_test=False, clock=time.time):
        u = urlsplit(url)
        if u.scheme != 'wss' and not (allow_local_test and u.scheme == 'ws' and u.hostname in ('127.0.0.1', 'localhost')):
            raise ValueError('WSS required')
        self.url, self.token, self.identity = url, token, identity
        self.clock = clock
        self.scope = json.dumps([identity.app, identity.group, identity.device])
        self.journal = Journal(state_path, self.scope, clock) if state_path else None
        self.cleaner = None
        self.pending, self.streams = {}, {}
        self.events = asyncio.Queue(64)
        self.ws, self.reader = None, None

    async def __aenter__(self):
        self.ws = await connect(self.url, additional_headers={'Authorization': 'Bearer '+self.token}, subprotocols=['common-relay.v1'], compression=None, max_size=270336, max_queue=16, ping_interval=20, ping_timeout=20)
        welcome = json.loads(await asyncio.wait_for(self.ws.recv(), 10))
        expected = self.identity
        own = welcome.get('identity', {})
        if welcome.get('version') != 1 or (own.get('app'),own.get('group'),own.get('device'),own.get('public_key')) != (expected.app,expected.group,expected.device,expected.public_key):
            await self.ws.close()
            raise RelayError('Server identity does not match local credentials')
        self.reader = asyncio.create_task(self._read())
        if self.journal:
            self.cleaner = asyncio.create_task(self._cleanup_loop())
        return self

    async def __aexit__(self, *args):
        if self.ws:
            await self.ws.close()
        if self.reader:
            self.reader.cancel()
            await asyncio.gather(self.reader, return_exceptions=True)
        if self.cleaner:
            self.cleaner.cancel()
            await asyncio.gather(self.cleaner, return_exceptions=True)
        if self.journal:
            self.journal.close()

    def cleanup(self):
        if self.journal:
            self.journal.cleanup()

    async def _cleanup_loop(self):
        try:
            while True:
                await asyncio.sleep(3600)
                self.cleanup()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never keep sending when durable state can no longer be maintained.
            if self.ws:
                await self.ws.close()
            raise

    async def send_event(self, event):
        await self.ws.send(json.dumps(event, separators=(',', ':')))

    async def request(self, event):
        object_id = event.setdefault('id', uuid.uuid4().hex)
        if object_id in self.pending:
            raise RelayError('Request already pending')
        future = asyncio.get_running_loop().create_future()
        self.pending[object_id] = future
        try:
            await self.send_event(event)
            return await asyncio.wait_for(future, 45)
        finally:
            self.pending.pop(object_id, None)

    async def peers(self):
        return (await self.request({'type': 'peers'}))['devices']

    async def send_online(self, recipient, data):
        """Queue an online frame; completion is not a server/device/business receipt."""
        object_id = uuid.uuid4().hex
        body = self.identity.seal(recipient, 'message', object_id, {'data': base64.b64encode(data).decode()})
        await self.send_event({'type': 'message', 'id': object_id, 'to': recipient, 'body': body, 'offline': False})

    async def message(self, recipient, data, *, offline=False, object_id=None, ttl=86400):
        object_id = object_id or uuid.uuid4().hex
        if offline and self.journal is None:
            raise RelayError('Persistent state required for offline delivery')
        expires = 0
        if offline:
            body, expires = self.journal.prepare(object_id, recipient, hashlib.sha256(data).hexdigest(), ttl,
                lambda expiry: self.identity.seal(recipient, 'message', object_id, {'data': base64.b64encode(data).decode(), 'expires': expiry}))
            if body is None:
                return {'type': 'received', 'id': object_id}
            ttl = expires-int(self.clock())
        else:
            body = self.identity.seal(recipient, 'message', object_id, {'data': base64.b64encode(data).decode()})
        result = await self.request({'type': 'message', 'id': object_id, 'to': recipient, 'body': body, 'offline': offline, 'ttl': ttl, 'expires': expires})
        if offline and result['type'] == 'received':
            self.journal.complete(object_id)
        return result

    async def acknowledge(self, event):
        # Invoke only AFTER the application's durable transaction succeeds.
        if event.get('offline') and self.journal is None:
            raise RelayError('Persistent state required for offline acknowledgment')
        if self.journal:
            self.journal.acknowledge(event['from'], event['id'])
        if event.get('offline'):
            await self.request({'type': 'ack', 'id': event['id'], 'from': event['from']})

    async def open_stream(self, recipient):
        object_id = uuid.uuid4().hex
        encryptor = EncryptStream()
        stream = Stream(self, recipient, object_id, encryptor)
        self.streams[object_id] = stream
        try:
            response = await self.request({'type': 'stream.open', 'id': object_id, 'to': recipient, 'body': self.identity.seal(recipient, 'stream.open', object_id, encryptor.descriptor())})
            stream.decryptor = DecryptStream(self.identity.open(recipient, 'stream.accept', object_id, response['body']))
            return stream
        except BaseException:
            self.streams.pop(object_id, None)
            with contextlib.suppress(Exception):
                await self.send_event({'type':'stream.close','id':object_id})
            raise

    async def accept_stream(self, event):
        peer, object_id = event['from'], event['id']
        decryptor = DecryptStream(self.identity.open(peer, 'stream.open', object_id, event['body']))
        encryptor = EncryptStream()
        stream = Stream(self, peer, object_id, encryptor, decryptor)
        self.streams[object_id] = stream
        try:
            await self.request({'type': 'stream.accept', 'id': object_id, 'body': self.identity.seal(peer, 'stream.accept', object_id, encryptor.descriptor())})
            return stream
        except BaseException:
            self.streams.pop(object_id, None)
            raise

    async def _read(self):
        try:
            async for raw in self.ws:
                if isinstance(raw, bytes):
                    if not 42<=len(raw)<=65561 or raw[0]!=1:
                        raise RelayError('Invalid binary frame')
                    object_id, seq = raw[1:17].hex(), struct.unpack('>Q',raw[17:25])[0]
                    stream = self.streams.get(object_id)
                    if stream:
                        try:
                            stream.incoming.put_nowait((seq,raw[25:]))
                        except asyncio.QueueFull:
                            stream.abort()
                            await self.send_event({'type':'stream.close','id':object_id})
                    continue
                e = json.loads(raw)
                object_id = e.get('id')
                if e['type']=='stream.credit':
                    stream=self.streams.get(object_id)
                    if stream:
                        seq=e['sequence']
                        if not stream.acknowledged<=seq<=stream.tx:
                            raise RelayError('Invalid credit')
                        for _ in range(seq-stream.acknowledged):
                            stream.credit.release()
                        stream.acknowledged=seq
                    continue
                if e['type']=='stream.close':
                    stream = self.streams.pop(object_id,None)
                    if stream:
                        stream.abort()
                    pending=self.pending.get(object_id)
                    if pending and not pending.done():
                        pending.set_exception(RelayError('Stream closed'))
                    continue
                if e['type'] not in ('message','stream.open') and object_id in self.pending:
                    pending = self.pending[object_id]
                    if not pending.done():
                        if e['type']=='error':
                            pending.set_exception(RelayError(e.get('code','error')))
                        else:
                            pending.set_result(e)
                    continue
                if e['type']=='message':
                    if e.get('offline') and self.journal is None:
                        raise RelayError('Persistent state required for offline reception')
                    value=self.identity.open(e['from'],'message',object_id,e['body'])
                    if ('expires' in value and value['expires'] <= int(self.clock())) or (self.journal and self.journal.contains(e['from'], object_id)):
                        if e.get('offline'):
                            await self.send_event({'type':'ack','id':object_id,'from':e['from']})
                        continue
                    e['data']=base64.b64decode(value['data'],validate=True)
                if e['type'] in ('message','stream.open','peer.up','peer.down'):
                    self.events.put_nowait(e)
        finally:
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(RelayError('Connection closed'))
            for stream in self.streams.values():
                stream.abort()
            if self.ws:
                await self.ws.close()
