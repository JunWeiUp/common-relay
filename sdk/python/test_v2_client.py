import asyncio
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from nacl.public import PrivateKey
from common_relay import Client, Identity
from common_relay.files import Files, prepare, decrypt

ROOT = Path(__file__).resolve().parents[2]
ACCESS = 'interop-v2-access-1'



def _server_speaks_v1(binary):
    """common-relay removed v1 (and device-add) on 2026-11-22; v1-only SDK APIs cannot be exercised."""
    try:
        r = subprocess.run([binary, 'device-add'], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return 'unknown command' not in (r.stdout + r.stderr)

class V2ClientIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        binary = os.environ.get('COMMON_RELAY_BINARY', str(ROOT / 'build/common-relay'))
        if not Path(binary).exists():
            binary = str(self.dir / 'common-relay')
            subprocess.run(['go', 'build', '-o', binary, './cmd/common-relay'], cwd=str(ROOT), check=True)
        self.binary = binary
        if not _server_speaks_v1(binary):
            self.skipTest('needs device-add provisioning, removed with v1')
        keys = {name: PrivateKey.generate() for name in ('gateway', 'worker')}
        self.ids = {
            name: Identity(
                'worker-demo',
                'production',
                name,
                bytes(keys[name]).hex(),
                {other: bytes(keys[other].public_key).hex() for other in keys if other != name},
            )
            for name in keys
        }
        self.tokens = {}
        srv_data = self.dir / 'server'
        for name in keys:
            cred = self.dir / f'{name}.json'
            subprocess.run(
                [
                    binary, 'device-add',
                    '--data', str(srv_data),
                    '--app', 'worker-demo',
                    '--group', 'production',
                    '--device', name,
                    '--public-key', self.ids[name].public_key,
                    '--credential-out', str(cred),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            self.tokens[name] = json.loads(cred.read_text())['token']

        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.ws_url = f'ws://127.0.0.1:{port}/v2/ws'
        self.files_url = f'http://127.0.0.1:{port}/v2/files'
        (self.dir / 'access').write_text(hashlib.sha256(ACCESS.encode()).hexdigest())
        (self.dir / 'admin').write_text(hashlib.sha256(b'test-v2-admin-secret').hexdigest())
        self.server = subprocess.Popen(
            [
                binary, 'serve',
                '--data', str(srv_data),
                '--listen', f'127.0.0.1:{port}',
                '--disk-reserve', '0',
                '--access-password-file', str(self.dir / 'access'),
                '--v2-admin-hash-file', str(self.dir / 'admin'),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(100):
            try:
                r, w = await asyncio.open_connection('127.0.0.1', port)
                w.close()
                await w.wait_closed()
                break
            except OSError:
                await asyncio.sleep(0.02)
        else:
            self.fail('server did not start')

        # Wait for relay_v2.db schema initialization and register worker-demo space + devices
        v2db = srv_data / 'relay_v2.db'
        for _ in range(50):
            if v2db.exists():
                break
            await asyncio.sleep(0.02)
        con = sqlite3.connect(str(v2db))
        now = int(time.time())
        with con:
            con.execute(
                "INSERT OR IGNORE INTO v2_spaces(id, name, trust_level, created_at, app) VALUES(?,?,?,?,?)",
                ('production', 'Speech Service', 'strict_e2e', now, 'worker-demo'),
            )
            for name in ('gateway', 'worker'):
                th = hashlib.sha256(self.tokens[name].encode()).hexdigest()
                con.execute(
                    "INSERT OR REPLACE INTO v2_devices(id, name, public_key, token_hash, is_admin, revoked, created_at) VALUES(?,?,?,?,0,0,?)",
                    (name, name, self.ids[name].public_key, th, now),
                )
                con.execute(
                    "INSERT OR REPLACE INTO v2_space_members(space_id, device_id, role, added_at) VALUES(?,?,?,?)",
                    ('production', name, 'member', now),
                )
        con.close()

    async def asyncTearDown(self):
        self.server.terminate()
        self.server.wait(timeout=10)
        self.tmp.cleanup()

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
