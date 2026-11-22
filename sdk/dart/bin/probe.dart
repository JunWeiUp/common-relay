import 'dart:convert';
import 'dart:io';
import 'package:common_relay/common_relay.dart';
import 'package:sodium/sodium.dart';
Future<void> main(List<String> args) async {
  if (args.length != 1) throw ArgumentError('Usage: probe.dart private-config.json');
  final c = jsonDecode(File(args[0]).readAsStringSync()) as Map<String, dynamic>;
  final sodium = await SodiumInit.init();
  if (c['group_action'] == null) throw ArgumentError('group_action required');
  {
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
}
