import asyncio
import unittest
from common_relay import Client
from common_relay.files import Files, prepare, decrypt
from relay_fixture import LoopbackRelay, binary

ACCESS = 'interop-v2-access-1'


class V2ClientIntegration(unittest.IsolatedAsyncioTestCase):
    """A gateway and a worker enrolled in one signed group."""

    async def asyncSetUp(self):
        server = binary()
        if server is None:
            self.skipTest('build/common-relay missing; run go build -o build/common-relay ./cmd/common-relay')
        self.relay = LoopbackRelay('worker-demo', ACCESS)
        self.addCleanup(self.relay.close)
        await self.relay.start(server)
        enrolled = await self.relay.enroll('gateway', 'worker')
        self.ids = {name: identity for name, (identity, _) in enrolled.items()}
        self.tokens = {name: token for name, (_, token) in enrolled.items()}
        self.dir, self.ws_url, self.files_url = self.relay.dir, self.relay.ws_url, self.relay.files_url

    def client(self, name):
        return Client(
            self.ws_url,
            self.tokens[name],
            self.ids[name],
            self.dir / f'{name}.sqlite',
            allow_local_test=True,
            password=ACCESS,
        )

    async def test_v2_ws_online_offline_receipt_and_files(self):
        # 1. Offline message while worker is disconnected -> stored, then delivered on connect + receipt marks complete
        async with self.client('gateway') as gw:
            res = await gw.message('worker', b'{"kind":"cancel","id":"job1"}', offline=True, object_id='11111111111111111111111111111111', ttl=300)
            self.assertEqual(res['type'], 'stored')

            async with self.client('worker') as wk:
                # Worker receives pending offline message
                ev = await asyncio.wait_for(wk.events.get(), 3)
                self.assertEqual(ev['type'], 'message')
                self.assertEqual(ev['from'], 'gateway')
                self.assertTrue(ev.get('offline'))
                self.assertEqual(ev['data'], b'{"kind":"cancel","id":"job1"}')
                await wk.acknowledge(ev)

                # Wait briefly for server to forward "received" receipt to gateway
                await asyncio.sleep(0.15)
                # Repeating the same offline message id must return "received" from completed journal
                res2 = await gw.message('worker', b'{"kind":"cancel","id":"job1"}', offline=True, object_id='11111111111111111111111111111111', ttl=300)
                self.assertEqual(res2['type'], 'received')

                # 2. Presence query works over /v2/ws
                peers = await gw.peers()
                self.assertIn('gateway', peers)
                self.assertIn('worker', peers)

                # 3. Online fire-and-forget messages (heartbeat / files_ready / progress)
                await wk.send_online('gateway', b'{"kind":"heartbeat","ready":true}')
                hb = await asyncio.wait_for(gw.events.get(), 3)
                self.assertEqual(hb['from'], 'worker')
                self.assertEqual(hb['data'], b'{"kind":"heartbeat","ready":true}')
                await gw.acknowledge(hb)

                await gw.send_online('worker', b'{"kind":"files_ready"}')
                fr = await asyncio.wait_for(wk.events.get(), 3)
                self.assertEqual(fr['from'], 'gateway')
                self.assertEqual(fr['data'], b'{"kind":"files_ready"}')
                await wk.acknowledge(fr)

        # 4. /v2/files resumable encrypted file upload -> inbox -> download -> decrypt -> ack
        gw_files = Files(self.files_url, self.tokens['gateway'], allow_local_test=True, password=ACCESS)
        wk_files = Files(self.files_url, self.tokens['worker'], allow_local_test=True, password=ACCESS)
        try:
            src = self.dir / 'audio.bin'
            src.write_bytes(b'fake-audio-payload-' * 1024)
            staged = self.dir / 'staged.enc'
            info = prepare(self.ids['gateway'], 'worker', src, staged, {'id': 'job2', 'kind': 'request'})
            await gw_files.upload(info, staged)
            inbox = await wk_files.inbox()
            self.assertEqual(len(inbox), 1)
            self.assertEqual(inbox[0]['id'], info['id'])
            dl = self.dir / 'dl.enc'
            out = self.dir / 'out.bin'
            await wk_files.download(inbox[0], dl)
            meta = decrypt(self.ids['worker'], 'gateway', inbox[0], dl, out)
            self.assertEqual(meta['id'], 'job2')
            self.assertEqual(out.read_bytes(), src.read_bytes())
            await wk_files.acknowledge(inbox[0]['id'])
            self.assertEqual(await wk_files.inbox(), [])
        finally:
            await gw_files.close()
            await wk_files.close()


if __name__ == '__main__':
    unittest.main()
