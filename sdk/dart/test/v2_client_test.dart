import 'dart:convert';
import 'dart:typed_data';
import 'package:common_relay/common_relay.dart';
import 'package:test/test.dart';
import 'vectors.dart';

void main() {
  test('matches protocol/v2/vectors.json and SyncApp routing policy', () {
    final v = vectors('vectors.json');
    for (final c in v['hash_secret'] as List) {
      expect(RelayV2Client.hashSecret(c['input'] as String), equals(c['sha256']), reason: c['use'] as String);
    }
    final f = v['binary_stream_frame'] as Map<String, dynamic>;
    final payload = Uint8List.fromList(utf8.encode(f['payload_utf8'] as String));
    final frame = RelayV2Client.encodeStreamFrame(f['stream_id'] as String, payload);
    expect(hex(frame), equals(f['frame_hex']));
    final decoded = RelayV2Client.decodeStreamFrame(unhex(f['frame_hex'] as String));
    expect(decoded.streamId, equals(f['stream_id']));
    expect(utf8.decode(decoded.payload), equals(f['payload_utf8']));

    expect(RelayV2Client.chooseRoute(lanReachable: true, peerOnline: true), equals(RelayV2Route.lanDirect));
    expect(RelayV2Client.chooseRoute(lanReachable: false, peerOnline: true), equals(RelayV2Route.pipeStream));
    expect(RelayV2Client.chooseRoute(lanReachable: false, peerOnline: false), equals(RelayV2Route.boxEphemeral));

    final c = RelayV2Client(baseUrl: 'https://relay.example/', accessPassword: 'acc', token: 'tok');
    expect(c.wsUrl, equals('wss://relay.example/v2/ws'));
    c.close();
    expect(
      () => RelayV2Client(baseUrl: 'http://relay.example', accessPassword: 'acc', token: 'tok'),
      throwsArgumentError,
    );
  });
}
