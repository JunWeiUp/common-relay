import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:common_relay/common_relay.dart';
import 'package:sodium/sodium.dart';
import 'package:test/test.dart';

void main() {
  test('Python envelope and final stream record interoperate', () async {
    final sodium = await SodiumInit.init();
    final v = jsonDecode(File('../../protocol/crypto-vectors.json').readAsStringSync()) as Map<String, dynamic>;
    final key = SecureKey.fromList(sodium, unhex(v['bob_secret'] as String));
    final bob = RelayIdentity(sodium: sodium, app: 'example', group: 'test', device: 'bob', secretKey: key, publicKey: unhex(v['bob_public'] as String), trustedPeers: {'alice': unhex(v['alice_public'] as String)});
    final id = v['id'] as String;
    expect(bob.open('alice', 'message', id, v['message'] as String)['data'], 'aGVsbG8=');
    expect(() => bob.open('alice', 'message', 'wrong', v['message'] as String), throwsStateError);
    expect(bob.open('alice', 'message', id, v['offline_message'] as String)['expires'], v['offline_expires']);
    final stream = RelayDecryptStream.create(sodium, v['stream_descriptor'] as Map<String, dynamic>);
    final aad = bob.aad('alice', 'bob', 'stream', id, 0);
    expect(utf8.decode(aad), v['stream_aad']);
    expect(await stream.pull(unhex(v['stream_ciphertext'] as String), aad), Uint8List.fromList(utf8.encode('hello')));
    expect(stream.finished, isTrue);
    await stream.close(); key.dispose();
  });
}
