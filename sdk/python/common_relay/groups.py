"""Authenticated group management. Persist config after every successful operation.

The invitation must arrive over a trusted out-of-band channel (QR/link). Never
learn the first signing key from the relay. No private key is uploaded.
"""
import base64
import copy
import hashlib
import json
import secrets
import re
from urllib.parse import urlsplit
import httpx
from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey
from .payload import SCHEMAS, strict

DOMAIN = b'common-relay/group-signing/v1\0'
def encode(value): return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
def digest(value): return hashlib.sha256(value).hexdigest()
def payload(entry):
    raw = base64.b64decode(entry['payload'], validate=True)
    if len(raw) > 32768 or base64.b64encode(raw).decode() != entry['payload']:
        raise ValueError('Non-canonical payload')
    return raw
def unpack(entry):
    raw = payload(entry)
    # Every signed payload is a state, join request or admission grant.
    if not any(strict(raw, schema) for schema in SCHEMAS): raise ValueError('Ambiguous signed payload')
    return json.loads(raw)
def signing(secret): return SigningKey(hashlib.sha256(DOMAIN + bytes.fromhex(secret)).digest())
def sign(value, secret, device):
    raw = encode(value)
    return {'payload': base64.b64encode(raw).decode(), 'signature': signing(secret).sign(raw).signature.hex(), 'signer': device}
def verify(entry, key): VerifyKey(bytes.fromhex(key)).verify(payload(entry), bytes.fromhex(entry['signature']))
def member(config, name):
    return {'device': config['device'], 'name': name, 'public_key': bytes(PrivateKey(bytes.fromhex(config['secret_key'])).public_key).hex(), 'signing_key': signing(config['secret_key']).verify_key.encode().hex(), 'manager': False}
def validate_state(state, app, group):
    members = state['members']; closed = state.get('closed', False)
    if state.get('version') != 1 or state.get('app') != app or state.get('group') != group or len(members) > 32 or (closed and members) or (not closed and not members): raise ValueError('Group mismatch')
    ids = [m['device'] for m in members]
    if len(ids) != len(set(ids)) or (not closed and not any(m['manager'] for m in members)): raise ValueError('Invalid membership')

def validate_grant(entry, owner, state):
    if not entry or entry.get('authorization') is not None or not owner['manager'] or entry['signer'] != owner['device']: raise ValueError('Invalid admission grant')
    verify(entry, owner['signing_key']); g = unpack(entry)
    if g.get('version') != 1 or g.get('purpose') != 'common-relay/admission/v1' or g.get('mode') != 'auto' or g.get('app') != state['app'] or g.get('group') != state['group'] or not 1 <= g['anchor_revision'] <= state['revision'] or g['expires'] <= 0: raise ValueError('Admission grant scope')
    for field, size in (('invitation',16),('secret_hash',32),('delegate_key',32),('anchor_hash',32)):
        if not re.fullmatch('[0-9a-f]{'+str(size*2)+'}', g[field]): raise ValueError('Admission grant encoding')
    return g

def advance_auto(current, entry, old, new, actor):
    grant = validate_grant(entry['authorization'], actor, old)
    verify(entry, grant['delegate_key'])
    before = {m['device']:m for m in old['members']}; after = {m['device']:m for m in new['members']}
    added = [m for k,m in after.items() if k not in before]
    if new.get('closed') or new['invitation'] != grant['invitation'] or not re.fullmatch('[0-9a-f]{64}',new['request_hash']) or len(added) != 1 or added[0]['manager'] or len(after) != len(before)+1 or any(after.get(k) != m for k,m in before.items()): raise ValueError('Invalid automatic admission')
    if old['revision'] == grant['anchor_revision'] and digest(payload(current)) != grant['anchor_hash']: raise ValueError('Admission anchor mismatch')
    return entry

def advance(current, entry):
    old, new = unpack(current), unpack(entry)
    validate_state(new, old['app'], old['group'])
    actor = next((m for m in old['members'] if m['device'] == entry['signer']), None)
    if not actor or old.get('closed'): raise ValueError('Untrusted manager')
    if entry.get('authorization') is None: verify(entry, actor['signing_key'])
    if new.get('name', '') != old.get('name', '') or new['revision'] != old['revision'] + 1 or new['previous'] != digest(payload(current)): raise ValueError('Broken membership chain')
    if entry.get('authorization') is not None: return advance_auto(current, entry, old, new, actor)
    before = {m['device']: m for m in old['members']}; after = {m['device']: m for m in new['members']}
    upgrades = set(); renamed = set()
    for k in before.keys() & after.keys():
        if before[k] != after[k]:
            same = dict(before[k]); same['name'] = after[k]['name']
            if same == after[k]: renamed.add(k); continue
            if before[k]['signing_key'] == '' and after[k]['signing_key'] and before[k]['public_key'] == after[k]['public_key']: upgrades.add(k)
            else: raise ValueError('Identity replacement')
    added, removed = (after.keys() - before.keys()) | upgrades, before.keys() - after.keys()
    if renamed:
        if len(renamed) != 1 or added or removed or new['invitation'] or new['request_hash'] or not (actor['manager'] or entry['signer'] in renamed): raise ValueError('Invalid rename')
        return entry
    if not ((new.get('closed') and actor['manager'] and not after and not new['invitation'] and not new['request_hash']) or
            (actor['manager'] and len(added) == 1 and not removed and new['invitation'] and new['request_hash']) or
            (len(removed) == 1 and not added and not new['invitation'] and not new['request_hash'] and (actor['manager'] or entry['signer'] in removed))):
        raise ValueError('Invalid membership transition')
    return entry

class Groups:
    def __init__(self, config, *, allow_local_test=False):
        self.config = config
        self.allow_local_test = allow_local_test
        u = urlsplit(config['url'])
        if u.username or getattr(u, "pass" + "word") or u.query or u.fragment or u.path != '/relay/v1/ws' or (u.scheme != 'wss' and not (allow_local_test and u.scheme == 'ws' and u.hostname == '127.0.0.1')): raise ValueError('WSS URL required')
        self.base = ('https' if u.scheme == 'wss' else 'http') + '://' + u.netloc + '/relay/v1'
    async def call(self, method, path, value=None, authorization=None):
        async with httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False) as session:
            async with session.stream(method, self.base + path, json=value, headers={'Authorization': authorization or 'Bearer ' + self.config.get('token', '')}) as response:
                if response.status_code != 200: raise RuntimeError(f'Group request failed ({response.status_code})')
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 3 * 1024 * 1024: raise ValueError('Response too large')
                return json.loads(raw)
    def accept(self, entry):
        state = unpack(entry)
        self.config['group_entry'] = entry
        self.config['trusted_peers'] = {m['device']: m['public_key'] for m in state['members'] if m['device'] != self.config['device']}
        self.config['public_key'] = member(self.config, self.config['device'])['public_key']
    async def refresh(self):
        current = self.config.get('group_entry')
        if not current: raise ValueError('Import an authenticated invitation or bootstrap first')
        while True:
            result = await self.call('GET', '/group?after=' + str(unpack(current)['revision']))
            for entry in result['entries']: current = advance(current, entry)
            self.accept(current)
            if not result['entries'] or unpack(current)['revision'] >= result['revision']: return {'state': unpack(current), 'online': result['online']}
    def prepare_create(self, group_name, device_name):
        if self.config.get('group_entry') or self.config.get('pending_join'): raise ValueError('Already enrolled or joining')
        if self.config.get('pending_create'): return
        if not 1 <= len(group_name.strip().encode()) <= 128 or not 1 <= len(device_name.strip().encode()) <= 128: raise ValueError('Name required (max 128 bytes)')
        if self.config.get('group'): raise ValueError('Existing group cannot be replaced')
        self.config['group'] = 'g-' + secrets.token_hex(16)
        self.config.setdefault('token', secrets.token_hex(32))
        own = member(self.config, device_name.strip()); own['manager'] = True
        self.config['pending_create'] = sign({'version': 1, 'app': self.config['app'], 'group': self.config['group'], 'name': group_name.strip(), 'revision': 1, 'previous': '', 'members': [own], 'invitation': '', 'request_hash': ''}, self.config['secret_key'], self.config['device'])
    async def create(self):
        entry = self.config['pending_create']
        await self.call('POST', '/group/create', {'entry': entry, 'token_hash': digest(self.config['token'].encode())})
        self.accept(entry); del self.config['pending_create']
    async def bootstrap(self, code, name):
        if code['app'] != self.config['app'] or code['group'] != self.config['group']: raise ValueError('Bootstrap scope')
        self.config.setdefault('token', secrets.token_hex(32))
        own = member(self.config, name); own['manager'] = True
        others = [{'device': k, 'name': k, 'public_key': v, 'signing_key': '', 'manager': False} for k,v in self.config.get('trusted_peers', {}).items() if k != own['device']]
        state = {'version': 1, 'app': code['app'], 'group': code['group'], 'revision': 1, 'previous': '', 'members': [own] + others, 'invitation': '', 'request_hash': ''}
        entry = sign(state, self.config['secret_key'], self.config['device'])
        await self.call('POST', '/group/bootstrap', {'entry': entry, 'token_hash': digest(self.config['token'].encode())}, 'Bootstrap ' + code['bootstrap'])
        self.accept(entry)
    async def invite(self, mode='manual', *, compact=False):
        import time
        if mode not in ('manual','auto'): raise ValueError('Unknown invitation mode')
        await self.refresh()
        current = self.config['group_entry']; state = unpack(current)
        own = next(m for m in state['members'] if m['device'] == self.config['device'])
        if not own['manager']: raise ValueError('Manager permission required')
        secret = secrets.token_hex(32)
        data = {'secret_hash': digest(secret.encode())}
        extra = {}
        if mode == 'auto':
            delegate = secrets.token_hex(32)
            grant = sign({'version':1, 'purpose':'common-relay/admission/v1', 'mode':'auto', 'app':state['app'], 'group':state['group'], 'invitation':secrets.token_hex(16), 'expires':int(time.time())+600, 'secret_hash':data['secret_hash'], 'delegate_key':signing(delegate).verify_key.encode().hex(), 'anchor_revision':state['revision'], 'anchor_hash':digest(payload(current))}, self.config['secret_key'], self.config['device'])
            data['mode'] = mode; data['grant'] = grant; extra = {'grant':grant, 'delegate_secret':delegate}
        result = await self.call('POST', '/group/invitations', data)
        if mode == 'auto' and (result.get('mode') != mode or result['id'] != unpack(data['grant'])['invitation'] or result['expires'] != unpack(data['grant'])['expires']): raise ValueError('Server does not support automatic admission')
        invitation = {'version': 1, 'mode':mode, 'url': self.config['url'], 'app': self.config['app'], 'group': self.config['group'], 'id': result['id'], 'expires': result['expires'], 'secret': secret, 'manager': own, **extra}
        if compact: await self.publish_invitation(invitation)
        return invitation
    async def publish_invitation(self, invitation):
        from . import invitation_links as links
        key=secrets.token_bytes(32);packet=links.seal(invitation,key,secrets.token_bytes(24))
        await self.call('POST','/group/invitations/'+invitation['id']+'/link',{'read_hash':digest(links.read_token(key).encode()),'packet':packet})
        invitation['short_link']=links.make_link(invitation,key)
        return invitation['short_link']
    async def resolve_invitation(self, text):
        import time
        from . import invitation_links as links
        url,identifier,key=links.parse_link(text.strip(),self.allow_local_test)
        endpoint=Groups({'url':url},allow_local_test=self.allow_local_test)
        result=await endpoint.call('GET','/enroll/'+identifier+'/link',authorization='InvitationLink '+links.read_token(key))
        if result.get('version')!=1: raise ValueError('Invalid invitation packet version')
        inv=links.open_packet(result['packet'],key)
        if inv.get('version')!=1 or inv.get('url')!=url or inv.get('id')!=identifier or inv.get('app')!=self.config['app'] or inv['expires']<=time.time(): raise ValueError('Invalid or expired invitation scope')
        return inv
    async def pending(self, invitation):
        result = await self.call('GET', '/group/invitations/' + invitation['id'])
        e = result['request']
        if e:
            j = unpack(e); verify(e, j['member']['signing_key'])
            if j['invitation'] != invitation['id'] or j['app'] != self.config['app'] or j['group'] != self.config['group'] or e['signer'] != j['member']['device']: raise ValueError('Join scope')
        return e
    async def join(self, invitation, name):
        import time
        if invitation['version'] != 1 or invitation['expires'] <= time.time() or any(invitation[k] != self.config[k] for k in ('url','app','group')): raise ValueError('Invalid or expired invitation')
        if invitation.get('mode','manual') not in ('manual','auto'): raise ValueError('Unknown invitation mode')
        if invitation.get('mode') == 'auto': self._invitation_grant(invitation)
        self.config.setdefault('token', secrets.token_hex(32))
        j = {'version': 1, 'app': self.config['app'], 'group': self.config['group'], 'invitation': invitation['id'], 'member': member(self.config,name), 'token_hash': digest(self.config['token'].encode())}
        pending = self.config.get('pending_join', {})
        entry = pending['request'] if pending.get('invitation', {}).get('id') == invitation['id'] else sign(j,self.config['secret_key'],self.config['device'])
        self.config['pending_join'] = {'invitation': invitation, 'request': entry}
        await self.call('POST','/enroll/'+invitation['id'],entry,'Invitation '+invitation['secret'])
    async def finish_join(self):
        pending = self.config['pending_join']; inv = pending['invitation']; req = unpack(pending['request'])
        if inv.get('mode') == 'auto': return await self._finish_auto(pending)
        result = await self.call('GET','/enroll/'+inv['id'],authorization='Claim '+self.config['token'])
        e = result['entry']
        if not e: return False
        if e.get('authorization') is not None: raise ValueError('Unexpected delegated approval')
        verify(e,inv['manager']['signing_key']);g=unpack(e);validate_state(g,self.config['app'],self.config['group'])
        own=next((m for m in g['members'] if m['device']==self.config['device']),None)
        expected=dict(req['member']);expected['manager']=own['manager'] if own else False
        if e['signer']!=inv['manager']['device'] or g['invitation']!=inv['id'] or g['request_hash']!=digest(payload(pending['request'])) or own!=expected: raise ValueError('Approval mismatch')
        self.accept(e);del self.config['pending_join'];return True
    def _invitation_grant(self, inv):
        g = unpack(inv['grant'])
        validate_grant(inv['grant'], inv['manager'], {'app':self.config['app'],'group':self.config['group'],'revision':g['anchor_revision']})
        if g['invitation'] != inv['id'] or g['expires'] != inv['expires'] or g['secret_hash'] != digest(inv['secret'].encode()) or g['delegate_key'] != signing(inv['delegate_secret']).verify_key.encode().hex(): raise ValueError('Invitation grant mismatch')
        return g
    async def _finish_auto(self, pending):
        inv = pending['invitation']; grant = self._invitation_grant(inv); req = unpack(pending['request'])
        current = None; after = grant['anchor_revision']-1
        while True:
            result = await self.call('GET', '/enroll/'+inv['id']+'/auto?after='+str(after), authorization='Claim '+self.config['token'])
            if not grant['anchor_revision'] <= result['revision'] <= 4096: raise ValueError('Admission revision')
            entries = result['entries']
            if not entries: raise ValueError('Incomplete admission chain')
            for e in entries:
                if current is None:
                    if digest(payload(e)) != grant['anchor_hash'] or unpack(e)['revision'] != grant['anchor_revision']: raise ValueError('Admission anchor mismatch')
                    validate_state(unpack(e),self.config['app'],self.config['group']); current = e
                else: current = advance(current,e)
            revision = unpack(current)['revision']
            if not after < revision <= result['revision']: raise ValueError('Admission revision')
            after = revision
            if after == result['revision']: break
        if result['entry']:
            if current != result['entry']: raise ValueError('Admission tip mismatch')
            e = current
        else:
            g = copy.deepcopy(unpack(current));g['members'].append(req['member']);g['revision']+=1;g['previous']=digest(payload(current));g['invitation']=inv['id'];g['request_hash']=digest(payload(pending['request']))
            e = sign(g,inv['delegate_secret'],inv['manager']['device']);e['authorization']=inv['grant'];advance(current,e)
            pending['auto_entry']=e
            result = await self.call('POST','/enroll/'+inv['id']+'/auto',e,'Claim '+self.config['token'])
            if result != e: raise ValueError('Admission response mismatch')
        g = unpack(e);own=next((m for m in g['members'] if m['device']==self.config['device']),None)
        if e.get('authorization') != inv['grant'] or g['invitation'] != inv['id'] or g['request_hash'] != digest(payload(pending['request'])) or own != req['member']: raise ValueError('Automatic approval mismatch')
        self.accept(e);del self.config['pending_join'];return True
    async def approve(self, invitation, request, *, manager=False):
        await self.refresh();j=unpack(request);verify(request,j['member']['signing_key'])
        if j['invitation']!=invitation['id'] or j['app']!=self.config['app'] or j['group']!=self.config['group']:raise ValueError('Join scope')
        g=copy.deepcopy(unpack(self.config['group_entry']));m=dict(j['member']);m['manager']=manager;g['members']=[v for v in g['members'] if v['device']!=m['device']]+[m];g['invitation']=invitation['id'];g['request_hash']=digest(payload(request))
        await self._change(g)
    async def remove(self, device):
        if device == self.config['device']: raise ValueError('Use exit for yourself')
        await self.refresh();g=copy.deepcopy(unpack(self.config['group_entry']));g['members']=[m for m in g['members'] if m['device']!=device];g['invitation']='';g['request_hash']='';await self._change(g)
    async def rename(self, device, name):
        name=name.strip()
        if not 1 <= len(name.encode()) <= 128: raise ValueError('Name required (max 128 bytes)')
        await self.refresh();g=copy.deepcopy(unpack(self.config['group_entry']));m=next(m for m in g['members'] if m['device']==device)
        if m['name']==name:return
        m['name']=name;g['invitation']='';g['request_hash']='';await self._change(g)
    async def prepare_exit(self, *, disband=False):
        if self.config.get('pending_exit'): return
        await self.refresh();old=self.config['group_entry'];g=copy.deepcopy(unpack(old));own=next(m for m in g['members'] if m['device']==self.config['device'])
        if disband and not own['manager']: raise ValueError('Manager permission required')
        g['members']=[] if disband else [m for m in g['members'] if m['device']!=self.config['device']]
        if not g['members']: g['closed']=True
        g['invitation']='';g['request_hash']='';g['revision']+=1;g['previous']=digest(payload(old))
        e=sign(g,self.config['secret_key'],self.config['device']);advance(old,e);self.config['pending_exit']=e
    async def exit(self):
        e=self.config['pending_exit']
        try:await self.call('POST','/group/exit',e)
        except RuntimeError as error:
            if '(409)' in str(error):self.config.pop('pending_exit',None)
            raise
        self.accept(e);del self.config['pending_exit']
    async def cancel(self, invitation): return await self.call('DELETE','/group/invitations/'+invitation['id'])
    async def _change(self,g):
        old=self.config['group_entry'];g['revision']+=1;g['previous']=digest(payload(old));e=sign(g,self.config['secret_key'],self.config['device']);advance(old,e)
        await self.call('PUT','/group',e);self.accept(e)
