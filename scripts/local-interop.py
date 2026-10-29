#!/usr/bin/env python3
"""Local-only SDK interop: temporary server, identities, journals; never reads .local/qa."""
import argparse
import asyncio
import contextlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from nacl.public import PrivateKey
from common_relay import Client, Identity

ROOT=Path(__file__).resolve().parents[1]
# TypeScript must be built first: (cd sdk/typescript && npm ci && npm run build).
NATIVE=['typescript','go','rust']
JVM_OR_SWIFT={'swift','java','kotlin'}

async def run(args, directory):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
    url=f'ws://127.0.0.1:{port}/relay/v1/ws'
    languages=['swift','dart','java'] + (['kotlin'] if args.kotlin else []) + NATIVE
    if args.only: languages=args.only
    if 'go' in languages: subprocess.run(['go','build','-o',str(directory/'go-probe'),'./examples/echo'],cwd=ROOT/'sdk/go',check=True)
    if 'rust' in languages: subprocess.run(['cargo','build','--quiet','--example','echo'],cwd=ROOT/'sdk/rust',check=True)
    keys={name:PrivateKey.generate() for name in ['python']+languages}
    configs={}
    for name,key in keys.items():
        credential=directory/(name+'-credential.json')
        subprocess.run([args.server,'device-add','--data',str(directory/'server'),'--app','interop','--group','local','--device',name,'--public-key',bytes(key.public_key).hex(),'--credential-out',str(credential)],check=True)
        c={'app':'interop','group':'local','device':name,'secret_key':bytes(key).hex(),'public_key':bytes(key.public_key).hex(),'trusted_peers':{n:bytes(k.public_key).hex() for n,k in keys.items() if n!=name},'url':url,'token':json.loads(credential.read_text())['token'],'allow_local_test':True,'state_path':str(directory/(name+'-state'))}
        path=directory/(name+'.json');path.write_text(json.dumps(c));path.chmod(0o600);configs[name]=c
    server=subprocess.Popen([args.server,'serve','--data',str(directory/'server'),'--listen',f'127.0.0.1:{port}','--disk-reserve','0'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                _,w=await asyncio.open_connection('127.0.0.1',port);w.close();await w.wait_closed();break
            except OSError: await asyncio.sleep(.05)
        else: raise RuntimeError('Local server did not start')
        for name in languages:
            config=directory/(name+'.json');env=dict(os.environ)
            if name=='swift': cmd=[args.swift,str(config)];cwd=ROOT
            elif name=='dart': cmd=[args.dart,'run','bin/probe.dart',str(config)];cwd=ROOT/'sdk/dart'
            elif name=='typescript': cmd=['node','examples/echo.mjs',str(config)];cwd=ROOT/'sdk/typescript'
            elif name=='go': cmd=[str(directory/'go-probe'),str(config)];cwd=ROOT
            elif name=='rust': cmd=[str(ROOT/'sdk/rust/target/debug/examples/echo'),str(config)];cwd=ROOT
            elif name=='kotlin':
                cmd=[args.gradle,'--offline',':testDebugUnitTest','--tests','*KotlinInteropTest','--rerun-tasks'];cwd=ROOT/'sdk/kotlin';env['COMMON_RELAY_QA_CONFIG']=str(config)
            else:
                cmd=[args.gradle,'--offline','testDebugUnitTest','--tests','*InteropTest','--rerun-tasks'];cwd=ROOT/'sdk/java';env['COMMON_RELAY_QA_CONFIG']=str(config)
            with (directory/(name+'.log')).open('w') as log:
                probe=subprocess.Popen(cmd,cwd=cwd,env=env,stdout=log,stderr=log)
                try:
                    c=configs['python'];identity=Identity(c['app'],c['group'],c['device'],c['secret_key'],c['trusted_peers'])
                    async with Client(url,c['token'],identity,directory/'python.db',allow_local_test=True) as client:
                        for _ in range(600):
                            if probe.poll() is not None: raise RuntimeError(f'{name} exited: '+(directory/(name+'.log')).read_text()[-4000:])
                            if any(d['device']==name for d in await client.peers()):break
                            await asyncio.sleep(.1)
                        else: raise RuntimeError(f'{name} failed to connect')
                        await client.message(name,b'durable interop',offline=True)
                        while True:
                            event=await asyncio.wait_for(client.events.get(),15)
                            if event['type']=='message':break
                        assert event['data']==b'durable interop' and event['offline']
                        await client.acknowledge(event)
                        stream=await client.open_stream(name);payload=os.urandom(8<<20)
                        sending=asyncio.create_task(stream.send(payload,final=True));received=bytearray()
                        while not stream.decryptor.finished:received.extend(await asyncio.wait_for(stream.receive(),30))
                        await sending;assert bytes(received)==payload;await stream.close()
                        print(json.dumps({'peer':name,'offline_both_directions':True,'stream_bytes_each_direction':len(payload),'result':'passed'}),flush=True)
                    if name in ('java','kotlin'):
                        code=await asyncio.to_thread(probe.wait,30)
                        if code:raise RuntimeError((directory/(name+'.log')).read_text()[-4000:])
                finally:
                    if probe.poll() is None:probe.terminate()
                    try:await asyncio.to_thread(probe.wait,10)
                    except subprocess.TimeoutExpired:probe.kill();probe.wait()
    finally:
        server.terminate();server.wait(timeout=10)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--server',required=True);p.add_argument('--swift');p.add_argument('--dart',default='dart');p.add_argument('--gradle');p.add_argument('--kotlin',action='store_true');p.add_argument('--only',nargs='+',choices=['swift','dart','java','kotlin',*NATIVE]);args=p.parse_args()
    selected=set(args.only or ['swift','java'])
    if 'swift' in selected and not args.swift: p.error('--swift is required for the Swift probe')
    if selected&{'java','kotlin'} and not args.gradle: p.error('--gradle is required for the Java/Kotlin probes')
    with tempfile.TemporaryDirectory(prefix='common-relay-interop-') as directory:
        asyncio.run(run(args,Path(directory)))
