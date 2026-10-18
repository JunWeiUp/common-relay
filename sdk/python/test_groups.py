import asyncio
import copy
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import unittest
from nacl.public import PrivateKey
from common_relay.groups import Groups, sign, unpack, payload, digest, member, verify, advance

ROOT=Path(__file__).resolve().parents[2]
class GroupTests(unittest.IsolatedAsyncioTestCase):
 async def asyncSetUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)
  with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
  self.url=f'ws://127.0.0.1:{port}/relay/v1/ws';self.server=ROOT/'build/common-relay'
  subprocess.run([str(self.server),'group-bootstrap','--data',str(self.path/'db'),'--app','example','--group','test','--credential-out',str(self.path/'bootstrap')],check=True)
  self.proc=subprocess.Popen([str(self.server),'serve','--self-service-apps','example','--data',str(self.path/'db'),'--listen',f'127.0.0.1:{port}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  for _ in range(100):
   try:_,w=await asyncio.open_connection('127.0.0.1',port);w.close();await w.wait_closed();break
   except OSError:await asyncio.sleep(.03)
  self.a=self.device('mac');await self.a.bootstrap(json.loads((self.path/'bootstrap').read_text()),'Mac')
 def device(self,id):
  key=PrivateKey.generate();return Groups({'url':self.url,'app':'example','group':'test','device':id,'secret_key':bytes(key).hex(),'public_key':bytes(key.public_key).hex(),'trusted_peers':{}},allow_local_test=True)
 async def asyncTearDown(self):self.proc.terminate();self.proc.wait(timeout=10);self.tmp.cleanup()
 async def add(self,host,new,manager=False):
  inv=await host.invite();await new.join(inv,new.config['device']);req=await host.pending(inv);await host.approve(inv,req,manager=manager);self.assertTrue(await new.finish_join());return inv
 async def test_compact_auto_and_manual_without_inviter_online(self):
  from common_relay import invitation_links as links
  for mode in ('auto','manual'):
   inv=await self.a.invite(mode,compact=True);link=inv['short_link'];self.assertLess(len(link),130)
   b=self.device('compact-'+mode);resolved=await b.resolve_invitation(link)
   self.assertNotIn('short_link',resolved);self.assertEqual(resolved['id'],inv['id'])
   await b.join(resolved,'Compact '+mode)
   if mode=='manual':
    self.assertFalse(await b.finish_join());await self.a.approve(inv,await self.a.pending(inv))
   self.assertTrue(await b.finish_join());await self.a.refresh()
   with self.assertRaises(RuntimeError):await self.device('replay').resolve_invitation(link)
 async def test_compact_packet_confidentiality_tamper_and_revocation(self):
  from common_relay import invitation_links as links
  inv=await self.a.invite('auto',compact=True);url,identifier,key=links.parse_link(inv['short_link'],True);b=self.device('reader')
  db=sqlite3.connect(self.path/'db/relay.db');row=db.execute('select read_hash,packet from group_invite_links where id=?',(identifier,)).fetchone()
  self.assertEqual(row[0],digest(links.read_token(key).encode()))
  for secret in (key.hex(),inv['secret'],inv['delegate_secret']):self.assertNotIn(secret,' '.join(row))
  with self.assertRaises(RuntimeError):await b.call('GET','/enroll/'+identifier+'/link',authorization='InvitationLink '+'00'*32)
  wrong=links.make_link(inv,bytes(32))
  with self.assertRaises(RuntimeError):await b.resolve_invitation(wrong)
  with self.assertRaises(RuntimeError):await self.a.call('POST','/group/invitations/'+identifier+'/link',{'read_hash':'11'*32,'packet':row[1]})
  import base64
  damaged=bytearray(base64.b64decode(row[1]));damaged[-1]^=1
  db.execute('update group_invite_links set packet=? where id=?',(base64.b64encode(damaged).decode(),identifier));db.commit();db.close()
  with self.assertRaises(Exception):await b.resolve_invitation(inv['short_link'])
  await self.a.cancel(inv)
  with self.assertRaises(RuntimeError):await b.resolve_invitation(inv['short_link'])
  db=sqlite3.connect(self.path/'db/relay.db');self.assertEqual(db.execute('select count(*) from group_invite_links').fetchone(),(0,));db.close()
 async def test_compact_cross_app_and_expiry(self):
  inv=await self.a.invite(compact=True);other=self.device('other-app');other.config['app']='other-app'
  with self.assertRaises(ValueError):await other.resolve_invitation(inv['short_link'])
  db=sqlite3.connect(self.path/'db/relay.db');db.execute('update group_invites set expires=0 where id=?',(inv['id'],));db.commit();db.close()
  with self.assertRaises(RuntimeError):await self.device('expired-link').resolve_invitation(inv['short_link'])
 async def test_auto_offline_inviter_concurrent_edits_and_restart(self):
  inv=await self.a.invite('auto');b=self.device('auto-phone');await b.join(inv,'Phone')
  await self.a.rename('mac','Renamed before join')
  # No inviter polling/approval calls after this point. Resume persisted request.
  b=Groups(json.loads(json.dumps(b.config)),allow_local_test=True)
  self.assertTrue(await b.finish_join());await self.a.refresh()
  self.assertFalse(next(m for m in unpack(b.config['group_entry'])['members'] if m['device']=='auto-phone')['manager'])
  await b.rename('auto-phone','My phone');await self.a.refresh()
  with self.assertRaises(RuntimeError):await self.device('second-claim').join(inv,'Other')
  await self.a.remove('auto-phone')
  with self.assertRaises(RuntimeError):await b.refresh()
 async def test_auto_lost_response_and_manual_cannot_escalate(self):
  inv=await self.a.invite('auto');b=self.device('auto');await b.join(inv,'Auto');saved=copy.deepcopy(b.config)
  req=await self.a.pending(inv)
  with self.assertRaises(RuntimeError):await self.a.approve(inv,req,manager=True)
  await b.finish_join();retry=Groups(saved,allow_local_test=True);self.assertTrue(await retry.finish_join())
  self.assertEqual(b.config['group_entry'],retry.config['group_entry'])
 async def test_auto_tamper_cancel_expiry_and_scope(self):
  inv=await self.a.invite('auto');b=self.device('bad')
  for field,value in [('mode','unknown'),('secret','0'*64),('delegate_secret','0'*64),('id','0'*32)]:
   bad=copy.deepcopy(inv);bad[field]=value
   with self.assertRaises(Exception):await b.join(bad,'Bad')
  bad=copy.deepcopy(inv);bad['grant']['signature']='00'*64
  with self.assertRaises(Exception):await b.join(bad,'Bad')
  await b.join(inv,'Bad');await self.a.cancel(inv)
  with self.assertRaises(RuntimeError):await b.finish_join()
  inv=await self.a.invite('auto');b=self.device('expired');await b.join(inv,'Expired')
  db=sqlite3.connect(self.path/'db/relay.db');db.execute('update group_invites set expires=0 where id=?',(inv['id'],));db.commit();db.close()
  with self.assertRaises(RuntimeError):await b.finish_join()
 async def test_auto_conflict_rebases_and_lost_post_response_recovers(self):
  inv=await self.a.invite('auto');b=self.device('rebase');await b.join(inv,'Rebase');call=b.call;changed=False
  async def concurrent(method,path,value=None,authorization=None):
   nonlocal changed
   if method=='POST' and path.endswith('/auto') and not changed:
    changed=True;await self.a.rename('mac','Concurrent')
   return await call(method,path,value,authorization)
  b.call=concurrent
  with self.assertRaisesRegex(RuntimeError,'409'):await b.finish_join()
  saved=copy.deepcopy(b.config);b=Groups(saved,allow_local_test=True);call=b.call
  async def lost(method,path,value=None,authorization=None):
   result=await call(method,path,value,authorization)
   if method=='POST' and path.endswith('/auto'):raise ConnectionError('Simulated lost response')
   return result
  b.call=lost
  with self.assertRaises(ConnectionError):await b.finish_join()
  b=Groups(copy.deepcopy(b.config),allow_local_test=True);self.assertTrue(await b.finish_join());await self.a.refresh()
  self.assertEqual(len(unpack(self.a.config['group_entry'])['members']),2)
 async def test_auto_endpoint_rejects_escalation_and_wrong_claim(self):
  inv=await self.a.invite('auto');b=self.device('hostile');await b.join(inv,'Hostile')
  path='/enroll/'+inv['id']+'/auto';auth='Claim '+b.config['token']
  with self.assertRaises(RuntimeError):await b.call('GET',path,authorization='Claim wrong')
  old=self.a.config['group_entry'];req=b.config['pending_join']['request'];g=copy.deepcopy(unpack(old));g['revision']+=1;g['previous']=digest(payload(old));g['members'].append(unpack(req)['member']);g['invitation']=inv['id'];g['request_hash']=digest(payload(req))
  for change in ('manager','rename','request','authorization'):
   bad=copy.deepcopy(g)
   if change=='manager':bad['members'][-1]['manager']=True
   if change=='rename':bad['members'][0]['name']='Altered'
   if change=='request':bad['request_hash']='00'*32
   e=sign(bad,inv['delegate_secret'],inv['manager']['device']);e['authorization']=copy.deepcopy(inv['grant'])
   if change=='authorization':e['authorization']['signature']='00'*64
   with self.subTest(change=change),self.assertRaises(RuntimeError):await b.call('POST',path,e,auth)
  self.assertEqual(len((await self.a.refresh())['state']['members']),1)
  self.assertTrue(await b.finish_join())
 async def test_invitation_mode_default_and_authorization_required(self):
  inv=await self.a.invite();inv.pop('mode');b=self.device('legacy-inv');await b.join(inv,'Legacy')
  self.assertFalse(await b.finish_join());await self.a.approve(inv,await self.a.pending(inv));self.assertTrue(await b.finish_join())
  for mode in ('unknown','auto'):
   with self.assertRaises(RuntimeError):await self.a.call('POST','/group/invitations',{'secret_hash':'ab'*32,'mode':mode})
  inv=await self.a.invite('auto');data={'secret_hash':digest(inv['secret'].encode()),'mode':'manual','grant':inv['grant']}
  with self.assertRaises(RuntimeError):await self.a.call('POST','/group/invitations',data)
 async def test_auto_revoked_inviter_and_consumed_invitation(self):
  admin=self.device('other-admin');await self.add(self.a,admin,True)
  inv=await self.a.invite('auto');b=self.device('waiting');await b.join(inv,'Waiting')
  await admin.remove('mac')
  with self.assertRaises(RuntimeError):await b.finish_join()
  inv=await admin.invite('auto');b=self.device('removed-after-admission');await b.join(inv,'New');pending=copy.deepcopy(b.config)
  await b.finish_join();await admin.remove(b.config['device'])
  with self.assertRaises(RuntimeError):await Groups(pending,allow_local_test=True).finish_join()
  db=sqlite3.connect(self.path/'db/relay.db');raw=' '.join(row[0] for row in db.execute('select grant_entry from group_invite_grants'));db.close()
  self.assertNotIn(inv['delegate_secret'],raw);self.assertNotIn(inv['secret'],raw)
 async def test_auto_paged_chain(self):
  inv=await self.a.invite('auto');b=self.device('paged');await b.join(inv,'Paged')
  for n in range(66):await self.a.rename('mac','Mac '+str(n))
  self.assertTrue(await b.finish_join());await self.a.refresh()
 async def test_manager_leaves_remaining_phone_can_invite_new_device(self):
  phone=self.device('remaining-phone');await self.add(self.a,phone,True)
  await self.a.prepare_exit();await self.a.exit()
  newcomer=self.device('new-device');await self.add(phone,newcomer)
  state=(await phone.refresh())['state'];self.assertEqual({m['device'] for m in state['members']},{'remaining-phone','new-device'})
 async def test_exit_rebases_after_concurrent_rename(self):
  b=self.device('member');await self.add(self.a,b)
  await self.a.prepare_exit(disband=True);await b.rename('member','Concurrent edit')
  with self.assertRaises(RuntimeError):await self.a.exit()
  self.assertNotIn('pending_exit',self.a.config)
  await self.a.prepare_exit(disband=True);await self.a.exit();self.assertTrue(unpack(self.a.config['group_entry'])['closed'])
 async def test_rename_permissions_and_identity_preservation(self):
  b=self.device('member');await self.add(self.a,b);old=copy.deepcopy(unpack(b.config['group_entry']))
  await b.rename('member','我的手机');await self.a.refresh();self.assertEqual(next(m for m in unpack(self.a.config['group_entry'])['members'] if m['device']=='member')['name'],'我的手机')
  with self.assertRaises(ValueError):await b.rename(self.a.config['device'],'Unauthorized')
  await self.a.rename('member','Family phone');await b.refresh();new=unpack(b.config['group_entry']);self.assertEqual(new['members'][1]['public_key'],old['members'][1]['public_key']);self.assertEqual(new['members'][1]['manager'],False)
  with self.assertRaises(ValueError):await b.rename('member','  ')
 async def test_leave_disband_permissions_and_lost_response(self):
  b=self.device('member');await self.add(self.a,b)
  with self.assertRaises(ValueError):await b.prepare_exit(disband=True)
  with self.assertRaises(ValueError):await self.a.prepare_exit()
  await b.prepare_exit();saved=copy.deepcopy(b.config);await b.exit();retry=Groups(saved,allow_local_test=True);await retry.exit()
  self.assertEqual(len((await self.a.refresh())['state']['members']),1)
  with self.assertRaises(RuntimeError):await b.refresh()
  c=self.device('second-manager');await self.add(self.a,c,True)
  await self.a.prepare_exit();await self.a.exit();self.assertEqual(len((await c.refresh())['state']['members']),1)
  inv=await c.invite();await c.prepare_exit(disband=True);saved=copy.deepcopy(c.config);await c.exit();await Groups(saved,allow_local_test=True).exit()
  self.assertTrue(unpack(c.config['group_entry'])['closed'])
  d=self.device('too-late')
  with self.assertRaises(RuntimeError):await d.join(inv,'Late')
  with self.assertRaises(RuntimeError):await c.refresh()
 async def test_only_device_exit_closes_group(self):
  await self.a.prepare_exit();await self.a.exit();self.assertTrue(unpack(self.a.config['group_entry'])['closed'])
 async def test_self_service_retry_and_invite(self):
  a=self.device('creator');del a.config['group'];a.prepare_create('我的设备','Phone')
  saved=copy.deepcopy(a.config);a.prepare_create('Ignored retry edit','Ignored');self.assertEqual(saved,a.config)
  await a.create();retry=Groups(copy.deepcopy(saved),allow_local_test=True);await retry.create()
  b=self.device('new-phone');b.config['group']=a.config['group'];await self.add(a,b,True)
  restored=Groups(copy.deepcopy(saved),allow_local_test=True);await restored.create();await restored.refresh()
  self.assertEqual(len(unpack(restored.config['group_entry'])['members']),2)
  self.assertEqual(unpack(restored.config['group_entry'])['name'],'我的设备')
  altered=unpack(restored.config['group_entry']);altered['name']='forged';altered['revision']+=1;altered['previous']=digest(payload(restored.config['group_entry']))
  with self.assertRaises(ValueError):advance(restored.config['group_entry'],sign(altered,restored.config['secret_key'],restored.config['device']))
 async def test_phone_invites_phone_remove_restart_and_isolation(self):
  b=self.device('phone-b');await self.add(self.a,b,True)
  c=self.device('phone-c');await self.add(b,c)
  roster=await self.a.refresh();self.assertEqual(len(roster['state']['members']),3)
  self.assertIn('phone-c',self.a.config['trusted_peers'])
  with self.assertRaises(RuntimeError):await c.call('POST','/group/invitations',{'secret_hash':'a'*64})
  foreign=copy.deepcopy(self.a.config);foreign['app']='other';foreign['group_entry']=copy.deepcopy(self.a.config['group_entry'])
  forged=unpack(self.a.config['group_entry']);forged['app']='other';forged['revision']+=1
  with self.assertRaises(RuntimeError):await self.a.call('PUT','/group',sign(forged,self.a.config['secret_key'],'mac'))
  old=copy.deepcopy(self.a.config['group_entry']);await self.a.remove('phone-c')
  with self.assertRaises(RuntimeError):await c.refresh()
  await b.refresh();self.assertNotIn('phone-c',b.config['trusted_peers'])
  with self.assertRaises(RuntimeError):await self.a.call('PUT','/group',old)
  with self.assertRaises(ValueError):await self.a.remove('mac')
  db=sqlite3.connect(self.path/'db/relay.db');tokens=[r[0] for r in db.execute('select token from devices')];db.close()
  self.assertNotIn(b.config['token'],tokens);self.assertIn(digest(b.config['token'].encode()),tokens)
  # A reconstructed client pins its persisted chain tip and fetches later events.
  restored=Groups(json.loads(json.dumps(b.config)),allow_local_test=True);self.assertEqual(len((await restored.refresh())['state']['members']),2)
 async def test_legacy_identity_upgrade_preserves_keys_and_token(self):
  a=self.device('legacy-manager');b=self.device('legacy-phone')
  for client in (a,b):
   client.config['group']='legacy'
   path=self.path/(client.config['device']+'-credential')
   subprocess.run([str(self.server),'device-add','--data',str(self.path/'db'),'--app','example','--group','legacy','--device',client.config['device'],'--public-key',client.config['public_key'],'--credential-out',str(path)],check=True)
   client.config['token']=json.loads(path.read_text())['token']
  a.config['trusted_peers']={b.config['device']:b.config['public_key']}
  b.config['trusted_peers']={a.config['device']:a.config['public_key']}
  boot=self.path/'legacy-bootstrap'
  subprocess.run([str(self.server),'group-bootstrap','--data',str(self.path/'db'),'--app','example','--group','legacy','--credential-out',str(boot)],check=True)
  await a.bootstrap(json.loads(boot.read_text()),'Manager')
  before=(b.config['secret_key'],b.config['token']);await self.add(a,b,True)
  self.assertEqual(before,(b.config['secret_key'],b.config['token']))
  self.assertEqual(len((await a.refresh())['state']['members']),2)
  self.assertTrue(next(m for m in unpack(b.config['group_entry'])['members'] if m['device']==b.config['device'])['manager'])

 async def test_invite_claim_expiry_tamper_and_approval(self):
  inv=await self.a.invite();b=self.device('b');c=self.device('c')
  wrong=copy.deepcopy(inv);wrong['secret']='0'*64
  with self.assertRaises(RuntimeError):await b.join(wrong,'B')
  await b.join(inv,'B');self.assertFalse(await b.finish_join())
  with self.assertRaises(RuntimeError):await c.join(inv,'C')
  req=await self.a.pending(inv);bad=copy.deepcopy(req);bad['signature']='00'*64
  with self.assertRaises(Exception):await self.a.approve(inv,bad)
  await self.a.approve(inv,req);self.assertTrue(await b.finish_join())
  wrong=copy.deepcopy(self.a.config['group_entry']);wrong['signature']='00'*64
  with self.assertRaises(Exception):verify(wrong,member(self.a.config,'A')['signing_key'])
  cancel=await self.a.invite();await self.a.cancel(cancel)
  with self.assertRaises(RuntimeError):await c.join(cancel,'C')
  expired=await self.a.invite();db=sqlite3.connect(self.path/'db/relay.db');db.execute('update group_invites set expires=0 where id=?',(expired['id'],));db.commit();db.close()
  with self.assertRaises(RuntimeError):await c.join(expired,'C')

class GroupVectors(unittest.TestCase):
 def test_shared_vectors(self):
  v=json.loads((ROOT/'protocol/group-vectors.json').read_text());verify(v['initial'],v['manager']['signing_key']);verify(v['request'],v['new_member']['signing_key']);advance(v['initial'],v['approved']);advance(v['approved'],v['removed'])
  self.assertEqual(member(v['config'],'Mac')['signing_key'],v['manager']['signing_key'])
  with self.assertRaises(Exception):advance(v['initial'],v['removed'])

 def test_auto_shared_vectors(self):
  v=json.loads((ROOT/'protocol/group-vectors.json').read_text());a=v['auto_admission'];advance(v['initial'],a['approved'])
  for case in a['invalid']:
   with self.subTest(case=case['case']),self.assertRaises(Exception):advance(v['initial'],case['entry'])
