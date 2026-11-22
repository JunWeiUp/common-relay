import json,unittest
from pathlib import Path
from common_relay import invitation_links as links

def v2_vectors():
 # Shared vectors predate v2; the packet crypto is unchanged, only the endpoint moves to /v2.
 v=json.loads((Path(__file__).resolve().parents[2]/'protocol/invitation-link-vectors.json').read_text())
 inv=dict(v['invitation'],url=v['invitation']['url'].replace('/relay/v1/ws','/v2/ws'))
 to_v2=lambda link:link if '/v2/i/' in link else link.replace('/i/','/v2/i/')
 return v,inv,to_v2(v['link']),to_v2(v['link_with_password']),bytes.fromhex(v['key'])

class InvitationLinkVectors(unittest.TestCase):
 def test_shared_encrypted_packet_and_tamper(self):
  v,inv,link,_,key=v2_vectors()
  self.assertEqual(links.open_packet(v['packet'],key),v['invitation']);self.assertEqual(links.read_token(key),v['read_token'])
  self.assertEqual(links.make_link(inv,key),link);self.assertEqual(links.parse_link(link),('wss://relay.example.com/v2/ws',inv['id'],key,None))
  with self.assertRaises(Exception):links.open_packet(v['packet'],bytes(32))
  with self.assertRaises(Exception):links.open_packet(v['packet'][:-8]+'AAAAAAAA',key)
  for text in (link+'=',link.replace('/v2/i/','/other/'),link.replace('relay.example.com','user@relay.example.com'),link.replace('#','?x=1#')):
   with self.subTest(text=text),self.assertRaises(Exception):links.parse_link(text)
 def test_link_carries_access_password(self):
  v,inv,link,with_password,key=v2_vectors()
  self.assertEqual(links.make_link(inv,key,v['access_password']),with_password)
  self.assertEqual(links.parse_link(with_password),('wss://relay.example.com/v2/ws',inv['id'],key,v['access_password']))
  for suffix in v['invalid_link_suffixes']:
   with self.subTest(suffix=suffix),self.assertRaises(ValueError):links.parse_link(link+suffix)
 def test_removed_v1_forms_rejected(self):
  v,inv,_,_,key=v2_vectors()
  with self.assertRaises(ValueError):links.parse_link(v['link'].replace('/v2/i/','/i/'))
  with self.assertRaises(ValueError):links.make_link(dict(inv,url='wss://relay.example.com/relay/v1/ws'),key)

if __name__=='__main__':unittest.main()
