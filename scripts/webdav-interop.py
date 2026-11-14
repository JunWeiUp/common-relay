#!/usr/bin/env python3
"""Local WebDAV upload -> Go encryption -> unmodified Python Files SDK -> ACK.
Starts the real server binary with --webdav-config on loopback using temporary
identities only. No production configuration.
"""
import argparse
import asyncio
import base64
import hashlib
import io
import json
import socket
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from nacl.public import PrivateKey
from common_relay.crypto import Identity
from common_relay.files import Files, decrypt


def dav(base, auth, method, path, body=None, headers=None):
    request = urllib.request.Request(base + urllib.parse.quote(path), data=body, method=method, headers={'Authorization': auth, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


async def run(server, root):
    keys = {name: PrivateKey.generate() for name in ('bridge', 'desktop')}
    tokens = {}
    for name, key in keys.items():
        out = root / (name + '.json')
        subprocess.run([server, 'device-add', '--data', str(root/'data'), '--app', 'interop', '--group', 'webdav', '--device', name, '--public-key', bytes(key.public_key).hex(), '--credential-out', str(out)], check=True)
        tokens[name] = json.loads(out.read_text())['token']
    secret = 'local-test-webdav-password-0123456789'
    hashed = subprocess.run([server, 'hash-password'], input=secret + '\n', capture_output=True, text=True, check=True).stdout.strip()
    assert hashed == hashlib.sha256(secret.encode()).hexdigest()
    config = root/'webdav.json'
    config.write_text(json.dumps([dict(route='backup', app='interop', group='webdav', sender='bridge', recipient='desktop', username='phone', password_sha256=hashed, secret_key=bytes(keys['bridge']).hex(), recipient_public_key=bytes(keys['desktop'].public_key).hex())]))
    config.chmod(0o600)
    password = 'local-test-access'
    access = root/'access.hash'
    access.write_text(hashlib.sha256(password.encode()).hexdigest())
    access.chmod(0o600)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    process = subprocess.Popen([server, 'serve', '--data', str(root/'data'), '--listen', f'127.0.0.1:{port}', '--disk-reserve', '0', '--access-password-file', str(access), '--webdav-config', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                with urllib.request.urlopen(base + '/healthz', timeout=1):
                    break
            except OSError:
                if process.poll() is not None:
                    raise RuntimeError('server exited')
                await asyncio.sleep(.05)
        else:
            raise RuntimeError('server startup timeout')
        dav_base = base + '/relay/v1/dav/backup'
        auth = 'Basic ' + base64.b64encode(b'phone:' + secret.encode()).decode()
        assert dav(dav_base, 'Basic ' + base64.b64encode(b'phone:wrong').decode(), 'PROPFIND', '/')[0] == 401
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('export.xls', b'sample spreadsheet bytes ' * 200)
        payload = buffer.getvalue()
        assert dav(dav_base, auth, 'MKCOL', '/备份/')[0] == 201
        assert dav(dav_base, auth, 'PUT', '/备份/backup.zip', payload, {'Content-Type': 'application/zip'})[0] == 201
        status, listing = dav(dav_base, auth, 'PROPFIND', '/备份/', headers={'Depth': '1'})
        assert status == 207 and 'backup.zip' in listing, listing
        assert dav(dav_base, auth, 'GET', '/备份/backup.zip')[0] == 403
        assert dav(dav_base, auth, 'PUT', '/备份/backup.zip', payload)[0] == 204  # unchanged: not queued again
        identity = Identity('interop', 'webdav', 'desktop', bytes(keys['desktop']).hex(), {'bridge': bytes(keys['bridge'].public_key).hex()})
        files = Files(base + '/relay/v1/files', tokens['desktop'], password=password, allow_local_test=True)
        try:
            inbox = await files.inbox()
            assert len(inbox) == 1, inbox
            info = inbox[0]
            cipher, plain = root/'cipher', root/'plain'
            await files.download(info, cipher)
            metadata = decrypt(identity, 'bridge', info, cipher, plain)
            assert metadata['type'] == 'webdav' and metadata['path'] == '/备份/backup.zip' and metadata['size'] == len(payload), metadata
            assert metadata['sha256'] == hashlib.sha256(payload).hexdigest()
            assert plain.read_bytes() == payload
            with zipfile.ZipFile(plain) as archive:
                assert archive.namelist() == ['export.xls']
            await files.acknowledge(info['id'])
            assert await files.inbox() == []
        finally:
            await files.close()
        print('PASS: WebDAV PUT -> Go encrypted file -> Python decrypt -> ACK; unchanged re-upload not queued')
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='relay-webdav-interop-') as directory:
        asyncio.run(run(str(Path(args.server).resolve()), Path(directory)))
