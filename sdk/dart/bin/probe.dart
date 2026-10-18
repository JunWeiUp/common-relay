import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'dart:async';
import 'package:common_relay/common_relay.dart';
import 'package:sodium/sodium.dart';
Future<void> main(List<String> args) async {
  if (args.length != 1) throw ArgumentError('Usage: probe.dart private-config.json');
  final c = jsonDecode(File(args[0]).readAsStringSync()) as Map<String, dynamic>;
  final sodium = await SodiumInit.init();
  if (c['group_action'] != null) {
    final g = RelayGroups(sodium,c,allowLocalTest:true);dynamic result = <String,dynamic>{};
    switch(c['group_action']) {
      case 'rename': await g.rename(c['device'] as String,'Updated device');break;
      case 'leave': await g.prepareExit();await g.exit();break;
      case 'disband': await g.prepareExit(disband:true);await g.exit();break;
      case 'create': c.remove('group');g.prepareCreate('My devices','Creator');await g.create();break;
      case 'join': await g.join(c['invitation_link'] == null ? c['invitation'] as Map<String,dynamic> : await g.resolveInvitation(c['invitation_link'] as String),c['device'] as String);break;
      case 'finish': result = await g.finishJoin();break;
      case 'invite': result = await g.invite(mode:c['invite_mode'] as String? ?? 'manual',compact:c['compact'] == true);break;
      case 'approve': await g.approve(c['invitation'] as Map<String,dynamic>,c['request'] as Map<String,dynamic>);break;
      case 'remove': await g.remove(c['remove'] as String);break;
      default: result = await g.refresh();
    }
    g.config['result'] = result;File(args[0]).writeAsStringSync(jsonEncode(g.config));return;
  }
  final identity = RelayIdentity(sodium: sodium, app: c['app'] as String, group: c['group'] as String, device: c['device'] as String, secretKey: SecureKey.fromList(sodium, unhex(c['secret_key'] as String)), publicKey: unhex(c['public_key'] as String), trustedPeers: (c['trusted_peers'] as Map<String, dynamic>).map((name, key) => MapEntry(name, unhex(key as String))));
  final client = RelayClient(identity, journal: c['state_path'] == null ? null : RelayJournal(Directory(c['state_path'] as String)));
  await client.connect(c['url'] as String, c['token'] as String, allowLocalTest: c['allow_local_test'] == true);
  stdout.writeln('READY');
  await for (final event in client.events) {
    if (event['type'] == 'stream.open') {
      unawaited(() async { final stream = await client.acceptStream(event); while (!stream.receivedFinal) { final data = await stream.receive(); await stream.send(data, finalRecord: stream.receivedFinal); } }());
    } else if (event['type'] == 'message') {
      await client.message(event['from'] as String, event['data'] as Uint8List, offline: event['offline'] == true);
      if (event['offline'] == true) await client.acknowledge(event);
    }
  }
}
