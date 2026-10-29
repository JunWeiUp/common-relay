#!/usr/bin/env python3
"""Python ↔ TypeScript/Go/Rust online messaging, using only ephemeral local identities."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from nacl.public import PrivateKey
from common_relay import Client, Identity

ROOT = Path(__file__).resolve().parents[1]

async def run(args, directory):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    url = f'ws://127.0.0.1:{port}/relay/v1/ws'
    keys = {name: PrivateKey.generate() for name in ('python', 'typescript', 'go', 'rust')}
    configs = {}
    for name, key in keys.items():
        credential = directory / (name + '-credential.json')
        subprocess.run([args.server, 'device-add', '--data', str(directory/'server'), '--app', 'interop', '--group', 'lightweight', '--device', name, '--public-key', bytes(key.public_key).hex(), '--credential-out', str(credential)], check=True, stdout=subprocess.DEVNULL)
        c = {'app':'interop', 'group':'lightweight', 'device':name, 'secret_key':bytes(key).hex(), 'trusted_peers':{n:bytes(k.public_key).hex() for n,k in keys.items() if n!=name}, 'url':url, 'token':json.loads(credential.read_text())['token'], 'allow_local_test':True}
        path=directory/(name+'.json');path.write_text(json.dumps(c));path.chmod(0o600);configs[name]=c
    subprocess.run(['go', 'build', '-o', str(directory/'go-probe'), './examples/echo'],cwd=ROOT/'sdk/go',check=True)
    subprocess.run(['cargo', 'build', '--quiet', '--release', '--example', 'echo'],cwd=ROOT/'sdk/rust',check=True)
    server=subprocess.Popen([args.server,'serve','--data',str(directory/'server'),'--listen',f'127.0.0.1:{port}','--disk-reserve','0'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                _,w=await asyncio.open_connection('127.0.0.1',port);w.close();await w.wait_closed();break
            except OSError:await asyncio.sleep(.05)
        else:raise RuntimeError('Local server failed to start')
        for name in ('typescript','go','rust'):
            c=configs['python'];identity=Identity(c['app'],c['group'],c['device'],c['secret_key'],c['trusted_peers'])
            async with Client(url,c['token'],identity,allow_local_test=True) as client:
                command={'typescript':['node',str(ROOT/'sdk/typescript/examples/echo.mjs')],'go':[str(directory/'go-probe')],'rust':[str(ROOT/'sdk/rust/target/release/examples/echo')]}[name]
                logpath=directory/(name+'.log')
                with logpath.open('w') as log:
                    probe=subprocess.Popen(command+[str(directory/(name+'.json'))],stdout=log,stderr=log)
                    try:
                        for _ in range(200):
                            if probe.poll() is not None:raise RuntimeError(logpath.read_text())
                            if 'READY' in logpath.read_text():break
                            await asyncio.sleep(.05)
                        else:raise RuntimeError('Probe not ready: '+logpath.read_text())
                        for payload in (b'', 'hello 世界'.encode(), os.urandom(100000)):
                            receipt=await client.message(name,payload,offline=False)
                            assert receipt['type']=='forwarded'
                            while True:
                                event=await asyncio.wait_for(client.events.get(),10)
                                if event['type']=='message':break
                            assert event['from']==name and event['data']==payload and not event.get('offline')
                        print(json.dumps({'peer':name,'online_messages_each_direction':3,'peer_discovery':True,'result':'passed'}),flush=True)
                    finally:
                        if probe.poll() is None:probe.terminate()
                        try:await asyncio.to_thread(probe.wait,10)
                        except subprocess.TimeoutExpired:probe.kill();probe.wait()
    finally:
        server.terminate();server.wait(timeout=10)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--server',required=True);args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='relay-lightweight-') as directory:asyncio.run(run(args,Path(directory)))
