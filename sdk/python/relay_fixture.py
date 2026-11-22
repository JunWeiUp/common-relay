"""Loopback relay for integration tests: a real `build/common-relay` with devices enrolled
through the signed group flow (self-service create + automatic invitations), exactly as
production devices are. No real identities; everything lives in a temporary directory."""
import asyncio
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from nacl.public import PrivateKey
from common_relay import Identity
from common_relay.groups import Groups

ROOT = Path(__file__).resolve().parents[2]
ADMIN = 'test-v2-admin-secret'


def binary():
    """Path of the prebuilt server, or None (build it with `go build -o build/common-relay ./cmd/common-relay`)."""
    path = Path(os.environ.get('COMMON_RELAY_BINARY', str(ROOT / 'build/common-relay')))
    return path if path.exists() else None


class LoopbackRelay:
    def __init__(self, app, access):
        self.app, self.access = app, access
        self.tmp = tempfile.TemporaryDirectory(prefix='common-relay-test-')
        self.dir = Path(self.tmp.name)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.ws_url = f'ws://127.0.0.1:{self.port}/v2/ws'
        self.files_url = f'http://127.0.0.1:{self.port}/v2/files'
        self.proc = None

    async def start(self, server):
        (self.dir / 'access').write_text(hashlib.sha256(self.access.encode()).hexdigest())
        (self.dir / 'admin').write_text(hashlib.sha256(ADMIN.encode()).hexdigest())
        self.proc = subprocess.Popen([str(server), 'serve', '--data', str(self.dir / 'server'), '--listen', f'127.0.0.1:{self.port}',
                                      '--disk-reserve', '0', '--self-service-apps', self.app,
                                      '--access-password-file', str(self.dir / 'access'), '--v2-admin-hash-file', str(self.dir / 'admin')],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(250):
            try:
                _, w = await asyncio.open_connection('127.0.0.1', self.port)
                w.close()
                await w.wait_closed()
                return
            except OSError:
                await asyncio.sleep(.02)
        raise RuntimeError('server did not start')

    async def enroll(self, *devices):
        """Create a group owned by devices[0] and admit the rest; returns {device: (Identity, token)}."""
        configs = []
        for device in devices:
            key = PrivateKey.generate()
            configs.append({'url': self.ws_url, 'password': self.access, 'app': self.app, 'device': device,
                            'secret_key': bytes(key).hex(), 'public_key': bytes(key.public_key).hex(), 'trusted_peers': {}})
        owner = Groups(configs[0], allow_local_test=True)
        owner.prepare_create('Test devices', devices[0])
        await owner.create()
        for config in configs[1:]:
            config['group'] = owner.config['group']
            peer = Groups(config, allow_local_test=True)
            await peer.join(await peer.resolve_invitation((await owner.invite('auto', compact=True))['short_link']), config['device'])
            if not await peer.finish_join():
                raise RuntimeError('automatic admission did not complete')
        for config in configs:
            await Groups(config, allow_local_test=True).refresh()
        self.group = owner.config['group']
        return {c['device']: (Identity(c['app'], c['group'], c['device'], c['secret_key'], c['trusted_peers']), c['token']) for c in configs}

    def close(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        self.tmp.cleanup()
