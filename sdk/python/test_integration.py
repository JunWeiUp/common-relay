import asyncio
import json
import os
from pathlib import Path
import unittest
from nacl.public import PrivateKey
from common_relay import Client, Identity
from common_relay.crypto import EncryptStream, DecryptStream
from common_relay.files import Files, prepare, decrypt
from relay_fixture import LoopbackRelay, binary

ROOT=Path(__file__).resolve().parents[2]


class CryptoTests(unittest.TestCase):
    def test_shared_offline_vector(self):
        v=json.loads((ROOT/'protocol/v2/crypto-vectors.json').read_text())
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

ACCESS='interop-access-1'

class Integration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        server=binary()
        if server is None:
            self.skipTest('build/common-relay missing; run go build -o build/common-relay ./cmd/common-relay')
        self.relay=LoopbackRelay('example',ACCESS);self.addCleanup(self.relay.close)
        await self.relay.start(server)
        enrolled=await self.relay.enroll('a','b')
        self.ids={name:identity for name,(identity,_) in enrolled.items()}
        self.tokens={name:token for name,(_,token) in enrolled.items()}
        self.dir,self.url,self.files_url=self.relay.dir,self.relay.ws_url,self.relay.files_url

    def client(self,name):
        return Client(self.url,self.tokens[name],self.ids[name],self.dir/(name+'.db'),allow_local_test=True,password=ACCESS)

    async def test_access_password_required(self):
        for password in (None, 'wrong-access-1'):
            client=Client(self.url,self.tokens['a'],self.ids['a'],allow_local_test=True,password=password)
            with self.assertRaises(Exception): await client.__aenter__()
        with self.assertRaises(ValueError): Client(self.url,self.tokens['a'],self.ids['a'],allow_local_test=True,password='short')

    async def test_endpoints_must_be_v2(self):
        for url in ('ws://127.0.0.1:1/relay/v1/ws','ws://127.0.0.1:1/'):
            with self.assertRaises(ValueError): Client(url,self.tokens['a'],self.ids['a'],allow_local_test=True,password=ACCESS)
        with self.assertRaises(ValueError): Files('http://127.0.0.1:1/relay/v1/files',self.tokens['a'],allow_local_test=True,password=ACCESS)

    async def test_offline_and_online_message(self):
        async with self.client('a') as a:
            result=await a.message('b',b'offline secret',offline=True)
            self.assertEqual(result['type'],'stored')
            async with self.client('b') as b:
                event=await asyncio.wait_for(b.events.get(),3)
                self.assertEqual(event['data'],b'offline secret')
                await b.acknowledge(event)
                await a.send_online('b', b'online without transport receipt')
                self.assertEqual((await asyncio.wait_for(b.events.get(),3))['data'], b'online without transport receipt')

    async def test_undecryptable_message_is_surfaced_not_fatal(self):
        # A receiver whose trust map lacks the sender (e.g. it left the group) gets an event and
        # keeps its connection; unacknowledged, the message is redelivered once trusted.
        async with self.client('a') as a:
            await a.message('b',b'from a',offline=True)
        stranger=Identity(self.ids['b'].app,self.ids['b'].group,'b',self.ids['b'].key.encode().hex(),{})
        async with Client(self.url,self.tokens['b'],stranger,self.dir/'b-stranger.db',allow_local_test=True,password=ACCESS) as b:
            event=await asyncio.wait_for(b.events.get(),3)
            self.assertEqual((event['type'],event['from'],event['trusted']),('undecryptable','a',False))
            await asyncio.sleep(.3)
            self.assertFalse(b.ws.closed if hasattr(b.ws,'closed') else False)
        async with self.client('b') as b:
            event=await asyncio.wait_for(b.events.get(),3)
            self.assertEqual((event['type'],event['data']),('message',b'from a'))
            await b.acknowledge(event)

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
                b.send_event = lose_ack
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
        a=Files(self.files_url,self.tokens['a'],allow_local_test=True,password=ACCESS)
        b=Files(self.files_url,self.tokens['b'],allow_local_test=True,password=ACCESS)
        try:
            info=await a.upload(info,staged)
            inbox=await b.inbox();self.assertEqual(len(inbox),1)
            downloaded=self.dir/'download';await b.download(info,downloaded)
            plain=self.dir/'plain';decrypt(self.ids['b'],'a',info,downloaded,plain)
            self.assertEqual(plain.read_bytes(),source.read_bytes())
            await b.acknowledge(info['id']);self.assertEqual(await b.inbox(),[])
        finally: await a.close();await b.close()

if __name__=='__main__': unittest.main()
