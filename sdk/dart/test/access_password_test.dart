import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:sodium/sodium.dart';
import 'package:common_relay/common_relay.dart';

void main() {
  const password = 'Abc-123!xyz';
  late Sodium sodium;
  late HttpServer server;
  final seen = <String, String?>{};
  setUpAll(() async => sodium = await SodiumInit.init());
  setUp(() async {
    seen.clear();
    server = await HttpServer.bind('127.0.0.1', 0);
    server.listen((r) async {
      seen[r.uri.path] = r.headers.value(relayAccessHeader);
      if (r.uri.path == '/relay/v1/group/state') {
        r.response.headers.contentType = ContentType.json;
        r.response.write(jsonEncode({'ok': true}));
      } else {
        r.response.statusCode = 401;
      }
      await r.response.close();
    });
  });
  tearDown(() => server.close(force: true));
  String ws() => 'ws://127.0.0.1:${server.port}/relay/v1/ws';

  test('invalid access passwords are rejected without echoing them', () {
    for (final bad in ['short', 'has space1', 'x' * 129, 'tab\tpassword', 'naïve-password']) {
      expect(() => relayAccessPassword(bad), throwsA(isA<ArgumentError>().having((e) => e.toString(), 'message', isNot(contains(bad)))));
      expect(() => RelayGroups(sodium, {'url': ws(), 'password': bad}), throwsArgumentError);
      expect(() => RelayFiles(Uri.parse('http://127.0.0.1/relay/v1/files'), 't', allowLocalTest: true, password: bad), throwsArgumentError);
    }
    expect(relayAccessPassword(password), password);
    expect(relayAccessPassword(null), isNull);
  });

  test('Relay-Access sent on group, invitation-link, file and WebSocket requests', () async {
    final groups = RelayGroups(sodium, {'url': ws(), 'token': 't', 'password': password}, allowLocalTest: true);
    expect(await groups.call('GET', '/group/state'), {'ok': true});
    final id = '00' * 16;
    final link = RelayInvitationLinks.make({'url': ws(), 'id': id}, Uint8List(32));
    await expectLater(groups.resolveInvitation(link), throwsA(anything));
    final files = RelayFiles(Uri.parse('http://127.0.0.1:${server.port}/relay/v1/files'), 't', allowLocalTest: true, password: password);
    await expectLater(files.inbox(), throwsStateError);
    await expectLater(files.acknowledge('f1'), throwsStateError);
    final kp = sodium.crypto.box.keyPair();
    final client = RelayClient(RelayIdentity(sodium: sodium, app: 'example', group: 'g', device: 'd', secretKey: kp.secretKey, publicKey: kp.publicKey, trustedPeers: {}));
    await expectLater(client.connect(ws(), 't', allowLocalTest: true, password: password), throwsA(anything));
    expect(seen['/relay/v1/group/state'], password);
    expect(seen['/relay/v1/enroll/$id/link'], password);
    expect(seen['/relay/v1/files'], password);
    expect(seen['/relay/v1/files/f1'], password);
    expect(seen['/relay/v1/ws'], password);
  });

  test('short link to a foreign relay does not receive the password', () async {
    final groups = RelayGroups(sodium, {'url': 'ws://127.0.0.1:1/relay/v1/ws', 'token': 't', 'password': password}, allowLocalTest: true);
    final id = '11' * 16;
    await expectLater(groups.resolveInvitation(RelayInvitationLinks.make({'url': ws(), 'id': id}, Uint8List(32))), throwsA(anything));
    expect(seen.containsKey('/relay/v1/enroll/$id/link'), isTrue);
    expect(seen['/relay/v1/enroll/$id/link'], isNull);
  });

  test('no Relay-Access header when password is absent', () async {
    final groups = RelayGroups(sodium, {'url': ws(), 'token': 't'}, allowLocalTest: true);
    await groups.call('GET', '/group/state');
    expect(seen.containsKey('/relay/v1/group/state'), isTrue);
    expect(seen['/relay/v1/group/state'], isNull);
  });
}
