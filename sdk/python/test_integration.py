import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from nacl.public import PrivateKey
from common_relay import Client, Identity, RelayError
from common_relay.crypto import EncryptStream, DecryptStream
from common_relay.files import Files, prepare, decrypt

ROOT=Path(__file__).resolve().parents[2]

class CryptoTests(unittest.TestCase):
    def test_shared_offline_vector(self):
        v=json.loads((ROOT/'protocol/crypto-vectors.json').read_text())
        bob=Identity(v['app'],v['group'],'bob',v['bob_secret'],{'alice':v['alice_public']})
        self.assertEqual(bob.open('alice','message',v['id'],v['offline_message'])['expires'],v['offline_expires'])

    def test_context_peer_and_tamper(self):
        ka,kb=PrivateKey.generate(),PrivateKey.generate()
        a=Identity('app','group','a',bytes(ka).hex(),{'b':bytes(kb.public_key).hex()})
        b=Identity('app','group','b',bytes(kb).hex(),{'a':bytes(ka.public_key).hex()})
        body=a.seal('b','message','x',{'payload':'secret'})
        self.assertEqual(b.open('a','message','x',body),{'payload':'secret'})
        with self.assertRaises(ValueError): b.open('a','message','y',body)
        with self.assertRaises(Exception): b.open('a','message','x',body[:-4]+'AAAA')
        enc=EncryptStream();dec=DecryptStream(enc.descriptor())
        cipher=enc.push(b'hello',b'context',True)
        self.assertEqual(dec.pull(cipher,b'context'),b'hello')
        with self.assertRaises(ValueError): dec.pull(cipher,b'context')

class Integration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.dir=Path(self.tmp.name)
        binary=os.environ.get('COMMON_RELAY_BINARY',str(ROOT/'build/common-relay'))
        keys={name:PrivateKey.generate() for name in ('a','b')}
        self.ids={name:Identity('example','group',name,bytes(keys[name]).hex(),{other:bytes(keys[other].public_key).hex() for other in keys if other!=name}) for name in keys}
        self.tokens={}
        for name in keys:
            file=self.dir/(name+'.json')
            subprocess.run([binary,'device-add','--data',str(self.dir/'server'),'--app','example','--group','group','--device',name,'--public-key',self.ids[name].public_key,'--credential-out',str(file)],check=True)
            self.tokens[name]=json.loads(file.read_text())['token']
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        self.url=f'ws://127.0.0.1:{port}/relay/v1/ws'
        self.files_url=f'http://127.0.0.1:{port}/relay/v1/files'
        self.server=subprocess.Popen([binary,'serve','--data',str(self.dir/'server'),'--listen',f'127.0.0.1:{port}','--disk-reserve','0'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                r,w=await asyncio.open_connection('127.0.0.1',port);w.close();await w.wait_closed();break
            except OSError: await asyncio.sleep(.02)
        else: self.fail('server did not start')

    async def asyncTearDown(self):
        self.server.terminate();self.server.wait(timeout=10);self.tmp.cleanup()

    def client(self,name):
        return Client(self.url,self.tokens[name],self.ids[name],self.dir/(name+'.db'),allow_local_test=True)

    async def test_encrypted_stream_and_offline_message(self):
        async with self.client('a') as a:
            result=await a.message('b',b'offline secret',offline=True)
            self.assertEqual(result['type'],'stored')
            async with self.client('b') as b:
                event=await asyncio.wait_for(b.events.get(),3)
                self.assertEqual(event['data'],b'offline secret')
                await b.acknowledge(event)
                await a.send_online('b', b'online without transport receipt')
                self.assertEqual((await asyncio.wait_for(b.events.get(),3))['data'], b'online without transport receipt')
                opening=asyncio.create_task(a.open_stream('b'))
                request=await asyncio.wait_for(b.events.get(),3)
                bs=await b.accept_stream(request);as_=await opening
                payload=os.urandom(8<<20)
                async def receive(stream):
                    result=bytearray()
                    while not stream.decryptor.finished:
                        result.extend(await stream.receive())
                    return bytes(result)
                sending=asyncio.create_task(as_.send(payload,final=True))
                self.assertEqual(await receive(bs),payload);await sending
                sending=asyncio.create_task(bs.send(payload,final=True))
                self.assertEqual(await receive(as_),payload);await sending
                await as_.close()

    async def test_lost_reply_restart_and_lost_ack(self):
        object_id = 'ab'*16
        async with self.client('a') as a:
            request = a.request
            async def lose_reply(event):
                await request(event)
                raise TimeoutError('simulated lost stored reply')
            a.request = lose_reply
            with self.assertRaises(TimeoutError):
                await a.message('b', b'durable', offline=True, object_id=object_id)
        async with self.client('a') as a:
            self.assertEqual((await a.message('b',b'durable',offline=True,object_id=object_id))['type'],'stored')
            with self.assertRaises(ValueError):
                await a.message('b',b'changed',offline=True,object_id=object_id)
            async with self.client('b') as b:
                event = await asyncio.wait_for(b.events.get(),3)
                async def lose_ack(event):
                    raise TimeoutError('simulated lost ack')
                b.request = lose_ack
                with self.assertRaises(TimeoutError):
                    await b.acknowledge(event)
            # Durable receiver journal automatically ACKs redelivery without exposing it again.
            async with self.client('b') as b:
                for _ in range(50):
                    result = await a.message('b',b'durable',offline=True,object_id=object_id)
                    if result['type']=='received': break
                    await asyncio.sleep(.02)
                self.assertEqual(result['type'],'received')
                self.assertTrue(b.events.empty())
                self.assertIsNone(a.journal.db.execute('SELECT body FROM outbox WHERE id=?',(object_id,)).fetchone()[0])

    async def test_encrypted_file_roundtrip(self):
        source=self.dir/'source';source.write_bytes(os.urandom(3<<20))
        staged=self.dir/'encrypted';info=prepare(self.ids['a'],'b',source,staged)
        a=Files(self.files_url,self.tokens['a'],allow_local_test=True)
        b=Files(self.files_url,self.tokens['b'],allow_local_test=True)
        try:
            info=await a.upload(info,staged)
            inbox=await b.inbox();self.assertEqual(len(inbox),1)
            downloaded=self.dir/'download';await b.download(info,downloaded)
            plain=self.dir/'plain';decrypt(self.ids['b'],'a',info,downloaded,plain)
            self.assertEqual(plain.read_bytes(),source.read_bytes())
            await b.acknowledge(info['id']);self.assertEqual(await b.inbox(),[])
        finally: await a.close();await b.close()

if __name__=='__main__': unittest.main()
