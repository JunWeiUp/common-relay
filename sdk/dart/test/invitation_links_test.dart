import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:sodium/sodium.dart';
import 'package:common_relay/common_relay.dart';
void main(){test('shared compact invitation encryption and tamper rejection',() async {
 final sodium=await SodiumInit.init();final v=jsonDecode(File('../../protocol/invitation-link-vectors.json').readAsStringSync()) as Map<String,dynamic>;
 final key=unhex(v['key'] as String),packet=v['packet'] as String,link=v['link'] as String;
 final inv=RelayInvitationLinks.open(sodium,packet,key);expect(inv,v['invitation']);expect(RelayInvitationLinks.readToken(key),v['read_token']);expect(RelayInvitationLinks.make(inv,key),link);expect(RelayInvitationLinks.parse(link).url,inv['url']);
 expect(RelayInvitationLinks.open(sodium,RelayInvitationLinks.seal(sodium,inv,key,unhex(v['nonce'] as String)),key),inv);
 expect(()=>RelayInvitationLinks.open(sodium,packet,Uint8List(32)),throwsA(anything));expect(()=>RelayInvitationLinks.parse('$link='),throwsA(anything));expect(()=>RelayInvitationLinks.parse(link.replaceFirst('relay.example.com','user@relay.example.com')),throwsA(anything));
});}
