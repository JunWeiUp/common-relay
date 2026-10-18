#!/usr/bin/env python3
"""Bounded transport soak using isolated QA identities; never sends application commands."""
import argparse,asyncio,json,os,tempfile,time
from pathlib import Path
from common_relay import Client,Identity
from common_relay.files import Files,prepare,decrypt

def identity(c):
    return Identity(c['app'],c['group'],c['device'],c['secret_key'],c['trusted_peers'])
async def event(client,kind):
    while True:
        value=await asyncio.wait_for(client.events.get(),30)
        if value['type']==kind:return value
async def cycle(a,b,root,files):
    ia,ib=identity(a),identity(b)
    async with Client(a['url'],a['token'],ia,root/'a.db') as ca, Client(b['url'],b['token'],ib,root/'b.db') as cb:
        payload=os.urandom(4096)
        await ca.send_online(ib.device,payload)
        received=await event(cb,'message');assert received['data']==payload
        await cb.send_online(ia.device,payload)
        assert (await event(ca,'message'))['data']==payload
        opening=asyncio.create_task(ca.open_stream(ib.device))
        incoming=await event(cb,'stream.open');bs=await cb.accept_stream(incoming);as_=await opening
        payload=os.urandom(256*1024)
        async def collect(stream):
            data=bytearray()
            while not stream.decryptor.finished:data.extend(await asyncio.wait_for(stream.receive(),30))
            return bytes(data)
        sending=asyncio.create_task(as_.send(payload,final=True))
        assert await collect(bs)==payload;await sending
        sending=asyncio.create_task(bs.send(payload,final=True))
        assert await collect(as_)==payload;await sending;await as_.close()
    if files:
        with tempfile.TemporaryDirectory(dir=root) as directory:
            d=Path(directory);source=d/'source';source.write_bytes(os.urandom(256*1024))
            info=prepare(ia,ib.device,source,d/'cipher')
            fa=Files(a['url'].replace('wss://','https://').replace('/ws','/files'),a['token'])
            fb=Files(b['url'].replace('wss://','https://').replace('/ws','/files'),b['token'])
            try:
                info=await fa.upload(info,d/'cipher');await fb.download(info,d/'download')
                decrypt(ib,ia.device,info,d/'download',d/'plain');assert (d/'plain').read_bytes()==source.read_bytes()
                await fb.acknowledge(info['id'])
            finally:await fa.close();await fb.close()
async def main():
    p=argparse.ArgumentParser();p.add_argument('--a',type=Path,required=True);p.add_argument('--b',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True);p.add_argument('--seconds',type=int,default=86400);p.add_argument('--metrics-host');args=p.parse_args()
    a=json.loads(args.a.read_text());b=json.loads(args.b.read_text())
    if a['app']!='common-relay-qa' or b['app']!='common-relay-qa':raise ValueError('Use isolated common-relay-qa devices only')
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.parent.chmod(0o700)
    fd=os.open(args.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    args.report.with_suffix('.pid').write_text(str(os.getpid()))
    start=time.monotonic();runs=failures=0
    with os.fdopen(fd,'w',buffering=1) as report:
        while time.monotonic()-start<args.seconds:
            sample={'elapsed_seconds':round(time.monotonic()-start,1),'iteration':runs+1}
            try:await asyncio.wait_for(cycle(a,b,args.report.parent,runs%5==0),90);sample['result']='passed'
            except Exception as error:failures+=1;sample.update(result='failed',error=type(error).__name__)
            if args.metrics_host:
                proc=await asyncio.create_subprocess_exec('ssh','-o','BatchMode=yes','-o','ConnectTimeout=5',args.metrics_host,'systemctl show common-relay -p MemoryCurrent --value',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
                try:
                    out,_=await asyncio.wait_for(proc.communicate(),10)
                    if proc.returncode==0:sample['server_memory_bytes']=int(out.strip())
                except Exception:
                    if proc.returncode is None:proc.kill();await proc.wait()
            runs+=1;report.write(json.dumps(sample)+'\n')
            remaining=args.seconds-(time.monotonic()-start)
            if remaining>0:await asyncio.sleep(min(60,remaining))
        report.write(json.dumps({'result':'completed' if failures==0 else 'completed_with_errors','elapsed_seconds':round(time.monotonic()-start,1),'iterations':runs,'failures':failures})+'\n')
if __name__=='__main__':asyncio.run(main())
