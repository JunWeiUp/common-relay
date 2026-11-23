"""Device messaging over the Common Relay v2 pipe (/v2/ws). Peer keys MUST be pinned out of band."""
import asyncio
import base64
from .access import access_headers
import json
import uuid
import hashlib
import time
from .journal import Journal
from urllib.parse import urlsplit
from websockets.asyncio.client import connect

class RelayError(Exception):
    pass

class Client:
    def __init__(self, url, token, identity, state_path=None, *, allow_local_test=False, clock=time.time, password=None):
        u = urlsplit(url)
        if u.scheme != 'wss' and not (allow_local_test and u.scheme == 'ws' and u.hostname in ('127.0.0.1', 'localhost')):
            raise ValueError('WSS required')
        if u.path != '/v2/ws':
            raise ValueError('Common Relay v2 endpoint (/v2/ws) required')
        self.url, self.token, self.identity = url, token, identity
        self._access = access_headers(password)
        self.clock = clock
        self.scope = json.dumps([identity.app, identity.group, identity.device])
        self.journal = Journal(state_path, self.scope, clock) if state_path else None
        self.cleaner = None
        self.pending = {}
        self.events = asyncio.Queue(64)
        self.ws, self.reader = None, None

    async def __aenter__(self):
        self.ws = await connect(self.url, additional_headers={'Authorization': 'Bearer '+self.token, **self._access}, compression=None, max_size=270336, max_queue=16, ping_interval=20, ping_timeout=20)
        welcome = json.loads(await asyncio.wait_for(self.ws.recv(), 10))
        if welcome.get('type') != 'hello' or welcome.get('from') != self.identity.device:
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
        return (await self.request({'type': 'presence', 'space': self.identity.group})).get('peers') or []

    async def send_online(self, recipient, data):
        """Queue an online frame; completion is not a server/device/business receipt."""
        object_id = uuid.uuid4().hex
        body = self.identity.seal(recipient, 'message', object_id, {'data': base64.b64encode(data).decode()})
        await self.send_event({'type': 'msg', 'space': self.identity.group, 'id': object_id, 'to': recipient, 'topic': 'msg', 'body': body, 'offline': False})

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
            ttl = max(1, expires-int(self.clock()))
        else:
            body = self.identity.seal(recipient, 'message', object_id, {'data': base64.b64encode(data).decode()})
        req = {'type': 'msg', 'space': self.identity.group, 'id': object_id, 'to': recipient, 'topic': 'msg', 'body': body, 'offline': offline}
        if offline:
            req['ttl'] = ttl
        result = await self.request(req)
        if result.get('type') == 'ack':
            ev = result.get('event')
            if ev == 'stored':
                result = {'type': 'stored', 'id': object_id}
            elif ev == 'forwarded':
                result = {'type': 'delivered', 'id': object_id}
        if offline and result.get('type') == 'received':
            self.journal.complete(object_id)
        return result

    async def acknowledge(self, event):
        # Invoke only AFTER the application's durable transaction succeeds.
        if event.get('offline') and self.journal is None:
            raise RelayError('Persistent state required for offline acknowledgment')
        if self.journal:
            self.journal.acknowledge(event['from'], event['id'])
        if event.get('offline'):
            await self.send_event({'type': 'ack', 'space': self.identity.group, 'id': event['id'], 'from': event['from']})

    async def _read(self):
        try:
            async for raw in self.ws:
                if isinstance(raw, bytes):
                    continue  # binary stream frames are not used by this client
                e = json.loads(raw)
                object_id = e.get('id')
                if e['type'] == 'received':
                    if self.journal and object_id:
                        self.journal.complete(object_id)
                    if object_id in self.pending:
                        pending = self.pending[object_id]
                        if not pending.done():
                            pending.set_result(e)
                    continue
                if e['type'] != 'msg' and object_id in self.pending:
                    pending = self.pending[object_id]
                    if not pending.done():
                        if e['type']=='error':
                            pending.set_exception(RelayError(e.get('code','error')))
                        else:
                            pending.set_result(e)
                    continue
                if e['type']=='msg':
                    if e.get('offline') and self.journal is None:
                        raise RelayError('Persistent state required for offline reception')
                    try:
                        value=self.identity.open(e['from'],'message',object_id,e['body'])
                    except Exception:
                        # Never fatal: closing the connection would make the relay redeliver this
                        # stored message forever. The app reconnects with fresh trusted keys when the
                        # sender is (now) a member, or acknowledges it to drop it for good.
                        self.events.put_nowait({'type':'undecryptable','id':object_id,'from':e['from'],
                                                'offline':bool(e.get('offline')),'trusted':e['from'] in self.identity.trusted})
                        continue
                    if ('expires' in value and value['expires'] <= int(self.clock())) or (self.journal and self.journal.contains(e['from'], object_id)):
                        if e.get('offline'):
                            await self.send_event({'type':'ack','space':self.identity.group,'id':object_id,'from':e['from']})
                        continue
                    e['data']=base64.b64decode(value['data'],validate=True)
                    e['type']='message'
                if e['type'] in ('message','peer.up','peer.down','group.changed'):
                    self.events.put_nowait(e)
        finally:
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(RelayError('Connection closed'))
            if self.ws:
                await self.ws.close()
