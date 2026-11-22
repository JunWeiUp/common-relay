import base64,hashlib,json,unittest
from pathlib import Path
from nacl.secret import SecretBox
from common_relay import invitation_links as links

V=json.loads((Path(__file__).resolve().parents[2]/'protocol/v2/invitation-link-vectors.json').read_text())
KEY=bytes.fromhex(V['key'])

class InvitationLinkVectors(unittest.TestCase):
 def test_shared_encrypted_packet_and_tamper(self):
  v,inv=V,V['invitation']
  self.assertEqual(links.open_packet(v['packet'],KEY),inv)
  self.assertEqual(links.seal(inv,KEY,bytes.fromhex(v['nonce'])),v['packet'])
  self.assertEqual(SecretBox(KEY).decrypt(base64.b64decode(v['packet'])),v['packet_plaintext'].encode())
  self.assertEqual(links.read_token(KEY),v['read_token'])
  self.assertEqual(hashlib.sha256(v['read_token'].encode()).hexdigest(),v['read_hash'])
  self.assertEqual(links.make_link(inv,KEY),v['link']);self.assertEqual(len(v['link']),v['link_length'])
  self.assertEqual(links.parse_link(v['link']),('wss://relay.example.com/v2/ws',inv['id'],KEY,None))
  with self.assertRaises(Exception):links.open_packet(v['packet'],bytes(32))
  with self.assertRaises(Exception):links.open_packet(v['packet'][:-8]+'AAAAAAAA',KEY)
  link=v['link']
  for text in (link+'=',link.replace('/v2/i/','/other/'),link.replace('relay.example.com','user@relay.example.com'),link.replace('#','?x=1#')):
   with self.subTest(text=text),self.assertRaises(Exception):links.parse_link(text)
 def test_link_carries_access_password(self):
  v,inv=V,V['invitation']
  self.assertEqual(links.make_link(inv,KEY,v['access_password']),v['link_with_password'])
  self.assertEqual(links.parse_link(v['link_with_password']),('wss://relay.example.com/v2/ws',inv['id'],KEY,v['access_password']))
  for suffix in v['invalid_link_suffixes']:
   with self.subTest(suffix=suffix),self.assertRaises(ValueError):links.parse_link(v['link']+suffix)
 def test_invalid_links_rejected(self):
  # Includes the removed legacy /i/ form.
  self.assertTrue(any('/i/' in l and '/v2/i/' not in l for l in V['invalid_links']))
  for text in V['invalid_links']:
   with self.subTest(text=text),self.assertRaises(ValueError):links.parse_link(text)
  with self.assertRaises(ValueError):links.make_link(dict(V['invitation'],url='wss://relay.example.com/relay/v1/ws'),KEY)

if __name__=='__main__':unittest.main()
