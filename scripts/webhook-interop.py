#!/usr/bin/env python3
"""Local Webhook -> Go encryption -> unmodified Python Files SDK -> ACK.
Uses only temporary identities and loopback HTTP. No production configuration.
"""
import argparse
import asyncio
import hashlib
import json
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from nacl.public import PrivateKey
from common_relay.crypto import Identity
from common_relay.files import Files, decrypt

ROOT = Path(__file__).resolve().parents[1]

async def run(server, root):
    vector = json.loads((ROOT / 'protocol/webhook-vectors.json').read_text())
    keys = {name: PrivateKey.generate() for name in ('bridge', 'mac')}
    tokens = {}
    for name, key in keys.items():
        out = root / (name + '.json')
        subprocess.run([server, 'device-add', '--data', str(root/'data'), '--app', 'interop', '--group', 'webhook', '--device', name, '--public-key', bytes(key.public_key).hex(), '--credential-out', str(out)], check=True)
        tokens[name] = json.loads(out.read_text())['token']
    token = 'local-test-webhook-token-' + 'a'*32
    config = root/'webhooks.json'
    config.write_text(json.dumps([dict(route='phone', app='interop', group='webhook', sender='bridge', recipient='mac', token_sha256=hashlib.sha256(token.encode()).hexdigest(), secret_key=bytes(keys['bridge']).hex(), recipient_public_key=bytes(keys['mac'].public_key).hex())]))
    config.chmod(0o600)
    password = 'local-test-access'
    access = root/'access.hash'
    access.write_text(hashlib.sha256(password.encode()).hexdigest())
    access.chmod(0o600)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    process = subprocess.Popen([server,'serve','--data',str(root/'data'),'--listen',f'127.0.0.1:{port}','--disk-reserve','0','--access-password-file',str(access),'--webhook-config',str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                with urllib.request.urlopen(base+'/healthz', timeout=1):
                    break
            except OSError:
                if process.poll() is not None: raise RuntimeError('server exited')
                await asyncio.sleep(.05)
        else: raise RuntimeError('server startup timeout')
        raw = json.dumps(vector['body'], ensure_ascii=False).encode()
        request = urllib.request.Request(base+'/relay/v1/webhooks/phone', data=raw, headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','Idempotency-Key':'local-event'})
        with urllib.request.urlopen(request, timeout=10) as response:
            assert response.status == vector['response_status']
            receipt = json.load(response)
        identity = Identity('interop','webhook','mac',bytes(keys['mac']).hex(),{'bridge':bytes(keys['bridge'].public_key).hex()})
        files = Files(base+'/relay/v1/files', tokens['mac'], password=password, allow_local_test=True)
        try:
            inbox = await files.inbox()
            assert len(inbox)==1 and inbox[0]['id']==receipt['id']
            info = inbox[0]
            assert info['expires']==vector['retained_expires']
            cipher, plain = root/'cipher', root/'plain'
            await files.download(info,cipher)
            metadata = decrypt(identity,'bridge',info,cipher,plain)
            assert all(metadata[k]==v for k,v in vector['metadata'].items())
            assert isinstance(metadata['received_at'],int)
            assert plain.read_bytes()==raw
            # Application would commit its DB transaction before this ACK.
            await files.acknowledge(info['id'])
            with urllib.request.urlopen(request,timeout=10) as response:
                assert json.load(response)['id']==receipt['id']
            assert await files.inbox()==[]
        finally:
            await files.close()
        print('PASS: Webhook -> Go encrypted file -> Python decrypt -> ACK -> deduplicated retry')
    finally:
        process.terminate()
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server',required=True)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='relay-webhook-interop-') as directory:
        asyncio.run(run(str(Path(args.server).resolve()),Path(directory)))
