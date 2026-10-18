#!/usr/bin/env python3
"""Probe running SDK echo peers over the configured real WSS service."""
import argparse,asyncio,hashlib,json,os
from pathlib import Path
from common_relay import Client,Identity

async def main():
    p=argparse.ArgumentParser();p.add_argument('--peer',required=True);p.add_argument('--bytes',type=int,default=8<<20);a=p.parse_args()
    directory=Path(__file__).resolve().parents[1]/'.local/qa';config=json.loads((directory/'python.json').read_text())
    identity=Identity(config['app'],config['group'],config['device'],config['secret_key'],config['trusted_peers'])
    async with Client(config['url'],config['token'],identity,directory/'python-receipts.db') as client:
        for _ in range(120):
            if any(d['device']==a.peer for d in await client.peers()):break
            await asyncio.sleep(1)
        else:raise RuntimeError('Peer did not connect')
        await client.message(a.peer,b'common-relay-v1 interop')
        echoed=await asyncio.wait_for(client.events.get(),15)
        while echoed['type']!='message':echoed=await asyncio.wait_for(client.events.get(),15)
        assert echoed['data']==b'common-relay-v1 interop'
        await client.acknowledge(echoed)
        stream=await client.open_stream(a.peer);payload=os.urandom(a.bytes)
        sending=asyncio.create_task(stream.send(payload,final=True));received=bytearray()
        while not stream.decryptor.finished:received.extend(await asyncio.wait_for(stream.receive(),45))
        await sending;assert bytes(received)==payload;await stream.close()
        print(json.dumps({'peer':a.peer,'bytes_each_direction':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'result':'passed'}))

asyncio.run(main())
