import 'dart:convert';
import 'dart:io';
import 'package:common_relay/common_relay.dart';
import 'package:test/test.dart';
import 'package:sodium/sodium.dart';

void main() {
  test('group changes reach the application after the authenticated welcome', () async {
    final native = await SodiumInit.init();
    final vector = jsonDecode(await File('../../protocol/crypto-vectors.json').readAsString()) as Map<String,dynamic>;
    final key = SecureKey.fromList(native, unhex(vector['alice_secret'] as String));
    final identity = RelayIdentity(sodium:native, app:'example', group:'test', device:'alice', secretKey:key, publicKey:unhex(vector['alice_public'] as String), trustedPeers:{});
    final client = RelayClient(identity);
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    WebSocket? peer;
    final subscription = server.listen((request) async {
      final ws = await WebSocketTransformer.upgrade(request, protocolSelector: (_) => 'common-relay.v1');
      peer = ws;
      ws.listen((_) {});
      ws.add(jsonEncode({'type':'welcome','version':1,'identity':{'app':'example','group':'test','device':'alice','public_key':hex(identity.publicKey)}}));
      ws.add(jsonEncode({'type':'group.changed','revision':2}));
    });
    try {
      final event = client.events.first;
      await client.connect('ws://127.0.0.1:${server.port}/relay/v1/ws', 'x' * 64, allowLocalTest:true);
      expect(await event.timeout(const Duration(seconds:3)), containsPair('revision',2));
    } finally {
      await client.close();
      await peer?.close();
      await subscription.cancel();
      await server.close(force:true);
      key.dispose();
    }
  });
}
