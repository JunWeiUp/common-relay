import 'dart:convert';
import 'dart:typed_data';
import 'package:common_relay/common_relay.dart';
import 'package:test/test.dart';

void main() {
  test('matches protocol/v2/vectors.json and SyncApp routing policy', () {
    expect(
      RelayV2Client.hashSecret('common-relay-v2-vector-secret'),
      equals('adc39f9ca5ad73f3c7e6aa2af6008c4e86e09e0d0c3596226b6b44ea82b20413'),
    );
    final payload = Uint8List.fromList(utf8.encode('ZIP_STREAM_CHUNK_DATA'));
    final frame = RelayV2Client.encodeStreamFrame('0123456789abcdef', payload);
    expect(
      hex(frame),
      equals('303132333435363738396162636465665a49505f53545245414d5f4348554e4b5f44415441'),
    );
    final decoded = RelayV2Client.decodeStreamFrame(frame);
    expect(decoded.streamId, equals('0123456789abcdef'));
    expect(utf8.decode(decoded.payload), equals('ZIP_STREAM_CHUNK_DATA'));

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
