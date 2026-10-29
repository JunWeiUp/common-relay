#!/usr/bin/env python3
"""Temporary loopback-only group enrollment across all SDKs; no real identities."""
import argparse,asyncio,json,os,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'sdk/python'))
from test_groups import GroupTests
ROOT=Path(__file__).resolve().parents[1]
# TypeScript must be built first: (cd sdk/typescript && npm ci && npm run build).
SDKS=('swift','dart','java','typescript','go','rust')
async def run(args):
 languages=args.only or SDKS
 fixture=GroupTests();await fixture.asyncSetUp()
 gobin=fixture.path/'go-groupprobe'
 if 'go' in languages:subprocess.run(['go','build','-o',str(gobin),'./examples/groupprobe'],cwd=ROOT/'sdk/go',check=True)
 if 'rust' in languages:subprocess.run(['cargo','build','--quiet','--example','group_probe'],cwd=ROOT/'sdk/rust',check=True)
 try:
  for lang in languages:
   peer=fixture.device(lang);inv=await fixture.a.invite();path=fixture.path/(lang+'.json');path.write_text(json.dumps(peer.config));path.chmod(0o600)
   async def operation(action,**extra):
    c=json.loads(path.read_text());c.update(extra);c['group_action']=action;path.write_text(json.dumps(c));env=dict(os.environ)
    if lang=='swift':cmd=[args.swift,str(path)];cwd=ROOT
    elif lang=='dart':cmd=[args.dart,'run','bin/probe.dart',str(path)];cwd=ROOT/'sdk/dart'
    elif lang=='typescript':cmd=['node','examples/group-probe.mjs',str(path)];cwd=ROOT/'sdk/typescript'
    elif lang=='go':cmd=[str(gobin),str(path)];cwd=ROOT
    elif lang=='rust':cmd=[str(ROOT/'sdk/rust/target/debug/examples/group_probe'),str(path)];cwd=ROOT
    else:cmd=[args.gradle,'--offline','testDebugUnitTest','--tests','*GroupInteropTest','--rerun-tasks'];cwd=ROOT/'sdk/java';env['COMMON_RELAY_GROUP_CONFIG']=str(path)
    p=await asyncio.create_subprocess_exec(*cmd,cwd=cwd,env=env,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT);out,_=await asyncio.wait_for(p.communicate(),90)
    if p.returncode:raise RuntimeError(out.decode()[-5000:])
    return json.loads(path.read_text()).get('result')
   await operation('join',invitation=inv);req=await fixture.a.pending(inv);await fixture.a.approve(inv,req,manager=True);assert await operation('finish')
   invite=await operation('invite');child=fixture.device(lang+'-child');await child.join(invite,'Phone child')
   enrolled=json.loads(path.read_text());from common_relay.groups import Groups
   host=Groups(enrolled,allow_local_test=True);request=await host.pending(invite)
   await operation('approve',invitation=invite,request=request);assert await child.finish_join()
   await operation('remove',remove=child.config['device']);await fixture.a.refresh()
   assert child.config['device'] not in fixture.a.config['trusted_peers']
   await operation('rename');await fixture.a.refresh();assert next(m for m in (await fixture.a.refresh())['state']['members'] if m['device']==peer.config['device'])['name']=='Updated device'
   # The inviter makes no further calls between issuing and the peer finishing.
   invite=await operation('invite',invite_mode='auto',compact=True);automatic=fixture.device(lang+'-auto-child');assert len(invite['short_link'])<130;await automatic.join(await automatic.resolve_invitation(invite['short_link']),'Automatic child');assert await automatic.finish_join()
   await operation('refresh');await operation('remove',remove=automatic.config['device'])
   await operation('leave');await fixture.a.refresh();assert peer.config['device'] not in fixture.a.config['trusted_peers']
   incoming=fixture.device(lang+'-auto-peer');path.write_text(json.dumps(incoming.config));auto_inv=await fixture.a.invite('auto',compact=True)
   await operation('join',invitation_link=auto_inv['short_link']);assert await operation('finish');await fixture.a.refresh()
   await operation('rename');await operation('leave');await fixture.a.refresh()

   fresh=fixture.device(lang+'-creator');path.write_text(json.dumps(fresh.config));await operation('create')
   created=json.loads(path.read_text());creator=Groups(created,allow_local_test=True);assert (await creator.refresh())['state']['name']=='My devices'
   invite=await operation('invite');new=fixture.device(lang+'-new');new.config['group']=created['group'];await new.join(invite,'Phone');request=await creator.pending(invite)
   await operation('approve',invitation=invite,request=request);assert await new.finish_join()
   await operation('disband')
   try:await new.refresh()
   except RuntimeError:pass
   else:raise AssertionError('Disband did not revoke peer')
   print(json.dumps({'sdk':lang,'self_service_create':True,'rename':True,'leave':True,'disband':True,'join':True,'auto_both_directions':True,'compact_both_directions':True,'invite_phone':True,'approve':True,'remove':True}),flush=True)
 finally:await fixture.asyncTearDown()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--swift');p.add_argument('--dart',default='dart');p.add_argument('--gradle');p.add_argument('--only',nargs='+',choices=SDKS);args=p.parse_args();selected=set(args.only or SDKS)
 if 'swift' in selected and not args.swift:p.error('--swift is required for the Swift probe')
 if 'java' in selected and not args.gradle:p.error('--gradle is required for the Java probe')
 asyncio.run(run(args))
