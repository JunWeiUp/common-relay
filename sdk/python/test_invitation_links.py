import json,unittest
from pathlib import Path
from common_relay import invitation_links as links

class InvitationLinkVectors(unittest.TestCase):
 def test_shared_encrypted_packet_and_tamper(self):
  v=json.loads((Path(__file__).resolve().parents[2]/'protocol/invitation-link-vectors.json').read_text());key=bytes.fromhex(v['key'])
  self.assertEqual(links.open_packet(v['packet'],key),v['invitation']);self.assertEqual(links.read_token(key),v['read_token']);self.assertEqual(links.make_link(v['invitation'],key),v['link']);self.assertEqual(links.parse_link(v['link']),('wss://relay.example.com/relay/v1/ws',v['invitation']['id'],key,None))
  with self.assertRaises(Exception):links.open_packet(v['packet'],bytes(32))
  with self.assertRaises(Exception):links.open_packet(v['packet'][:-8]+'AAAAAAAA',key)
  for text in (v['link']+'=',v['link'].replace('/i/','/other/'),v['link'].replace('relay.example.com','user@relay.example.com'),v['link'].replace('#','?x=1#')):
   with self.subTest(text=text),self.assertRaises(Exception):links.parse_link(text)
 def test_link_carries_access_password(self):
  v=json.loads((Path(__file__).resolve().parents[2]/'protocol/invitation-link-vectors.json').read_text());key=bytes.fromhex(v['key'])
  self.assertEqual(links.make_link(v['invitation'],key,v['access_password']),v['link_with_password'])
  self.assertEqual(links.parse_link(v['link_with_password']),('wss://relay.example.com/relay/v1/ws',v['invitation']['id'],key,v['access_password']))
  for suffix in v['invalid_link_suffixes']:
   with self.subTest(suffix=suffix),self.assertRaises(ValueError):links.parse_link(v['link']+suffix)
