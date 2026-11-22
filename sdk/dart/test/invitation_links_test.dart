import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:sodium/sodium.dart';
import 'package:common_relay/common_relay.dart';
void main(){test('shared compact invitation encryption and tamper rejection',() async {
 final sodium=await SodiumInit.init();final v=jsonDecode(File('../../protocol/invitation-link-vectors.json').readAsStringSync()) as Map<String,dynamic>;
 final key=unhex(v['key'] as String),packet=v['packet'] as String;
 final v1=RelayInvitationLinks.open(sodium,packet,key);expect(v1,v['invitation']);
 // Shared vectors predate the v1 removal; the v2 form only swaps the URL path and link prefix.
 final inv={...v1,'url':(v1['url'] as String).replaceFirst('/relay/v1/ws','/v2/ws')};final legacy=v['link'] as String,link=legacy.replaceFirst('/i/','/v2/i/');
 expect(()=>RelayInvitationLinks.parse(legacy),throwsA(anything));expect(()=>RelayInvitationLinks.make(v1,key),throwsA(anything));expect(RelayInvitationLinks.readToken(key),v['read_token']);expect(RelayInvitationLinks.make(inv,key),link);expect(RelayInvitationLinks.parse(link).url,inv['url']);
 expect(RelayInvitationLinks.open(sodium,RelayInvitationLinks.seal(sodium,inv,key,unhex(v['nonce'] as String)),key),inv);
 expect(()=>RelayInvitationLinks.open(sodium,packet,Uint8List(32)),throwsA(anything));expect(()=>RelayInvitationLinks.parse('$link='),throwsA(anything));expect(()=>RelayInvitationLinks.parse(link.replaceFirst('relay.example.com','user@relay.example.com')),throwsA(anything));
 final withPassword=(v['link_with_password'] as String).replaceFirst('/i/','/v2/i/'),access=v['access_password'] as String;
 expect(RelayInvitationLinks.make(inv,key,password:access),withPassword);final parsed=RelayInvitationLinks.parse(withPassword);
 expect(parsed.password,access);expect(parsed.key,key);expect(parsed.url,inv['url']);expect(RelayInvitationLinks.parse(link).password,isNull);
 for(final suffix in v['invalid_link_suffixes'] as List){expect(()=>RelayInvitationLinks.parse('$link$suffix'),throwsA(anything),reason:suffix as String);}
});}
