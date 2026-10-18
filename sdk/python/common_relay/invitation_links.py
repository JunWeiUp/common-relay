"""Authenticated compact invitations; fragment keys never enter HTTP requests."""
import base64, hashlib, json, re
from urllib.parse import urlsplit
from nacl.secret import SecretBox

PURPOSE = 'common-relay/invitation-link/v1'
READ_DOMAIN = b'common-relay/invitation-link/read/v1\0'
def b64url(raw): return base64.urlsafe_b64encode(raw).decode().rstrip('=')
def unb64url(text, size):
    if not re.fullmatch('[A-Za-z0-9_-]+',text): raise ValueError('Invalid compact invitation')
    raw=base64.urlsafe_b64decode(text+'='*(-len(text)%4))
    if len(raw)!=size or b64url(raw)!=text: raise ValueError('Invalid compact invitation')
    return raw
def read_token(key): return hashlib.sha256(READ_DOMAIN+key).hexdigest()
def seal(invitation,key,nonce):
    raw=json.dumps({'version':1,'purpose':PURPOSE,'invitation':invitation},separators=(',',':'),ensure_ascii=False).encode()
    return base64.b64encode(bytes(SecretBox(key).encrypt(raw,nonce))).decode()
def open_packet(packet,key):
    raw=base64.b64decode(packet,validate=True)
    if not 40 <= len(raw) <= 16384: raise ValueError('Invalid invitation packet')
    value=json.loads(SecretBox(key).decrypt(raw))
    if value.get('version')!=1 or value.get('purpose')!=PURPOSE: raise ValueError('Invalid invitation packet scope')
    return value['invitation']
def make_link(inv,key):
    return 'common-relay://'+urlsplit(inv['url']).netloc+'/i/'+b64url(bytes.fromhex(inv['id']))+'#'+b64url(key)
def parse_link(text,allow_local_test=False):
    if len(text)>2048: raise ValueError('Invitation link too long')
    u=urlsplit(text)
    if u.scheme!='common-relay' or not u.hostname or u.username or getattr(u,'pass'+'word') or u.query or not re.fullmatch('/i/[A-Za-z0-9_-]{22}',u.path): raise ValueError('Invalid compact invitation')
    scheme='ws' if allow_local_test and u.hostname=='127.0.0.1' else 'wss'
    return scheme+'://'+u.netloc+'/relay/v1/ws',unb64url(u.path[3:],16).hex(),unb64url(u.fragment,32)
