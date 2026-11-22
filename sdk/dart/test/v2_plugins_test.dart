import 'dart:convert';
import 'dart:typed_data';
import 'package:common_relay/common_relay.dart';
import 'package:crypto/crypto.dart' show sha256;
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sodium/sodium.dart';
import 'package:test/test.dart';
import 'vectors.dart';

const bindingJson = {
  'id': 'b1', 'plugin_id': 'webhook', 'mount': 'gh hooks', 'space_id': 'personal', 'box_name': 'inbox',
  'config_json': '{"tag":"x"}', 'enabled': true, 'updated_at': 7, 'config_version': 4,
  'secret_keys': ['token_sha256'], 'sealed': true,
  'summary': {'tag': 'x', 'has_token': true}, 'accounts': [{'scope_key': 's', 'username': 'u', 'mode': 'rw'}],
};

/// Test-only sealer mirroring Go SealStream so multi-frame payloads can be checked.
Uint8List sealForTest(Sodium sodium, Uint8List recipient, Uint8List plain, {int chunk = 64 << 10}) {
  final key = sodium.crypto.secretBox.keygen();
  final out = BytesBuilder()
    ..add(utf8.encode('CRS1'))
    ..add(sodium.crypto.box.seal(message: key.extractBytes(), publicKey: recipient));
  final prefix = sodium.randombytes.buf(16);
  out.add(prefix);
  var off = 0;
  for (var ctr = 0;; ctr++) {
    final end = off + chunk < plain.length ? off + chunk : plain.length;
    final last = end == plain.length;
    final nonce = Uint8List(24)..setRange(0, 16, prefix);
    ByteData.sublistView(nonce)
      ..setUint32(16, last ? 0x80000000 : 0)
      ..setUint32(20, ctr);
    final ct = sodium.crypto.secretBox.easy(message: Uint8List.sublistView(plain, off, end), nonce: nonce, key: key);
    out.add((ByteData(4)..setUint32(0, ct.length)).buffer.asUint8List());
    out.add(ct);
    off = end;
    if (last) break;
  }
  key.dispose();
  return out.takeBytes();
}

void main() {
  test('plugin admin requests are shaped like the Go client', () async {
    final seen = <http.Request>[];
    final mock = MockClient((req) async {
      seen.add(req);
      final p = req.url.path;
      if (p == '/v2/admin/plugins') {
        return http.Response(jsonEncode({
          'ok': true,
          'plugins': [
            {'id': 'webhook', 'required_trust': 'bridge_allowed', 'schema': [
              {'key': 'token', 'type': 'string', 'secret': true},
              {'key': 'tag', 'type': 'string', 'description': 'label', 'required': true},
            ]},
            {'id': 'old', 'required_trust': 'strict_e2e'},
          ],
        }), 200);
      }
      if (p.endsWith('/accounts')) {
        return http.Response(jsonEncode({'ok': true, 'account': {'binding_id': 'b1', 'scope_key': 's', 'username': 'u', 'mode': 'rw', 'meta_json': '', 'updated_at': 9}}), 200);
      }
      return http.Response(jsonEncode({'ok': true, 'binding': bindingJson}), 200);
    });
    final c = RelayV2Client(baseUrl: 'https://relay.example', accessPassword: 'acc', token: 'tok', httpClient: mock);

    final cat = await c.pluginCatalog();
    expect(cat.map((e) => e.id), ['webhook', 'old']);
    expect(cat[0].schema[0].secret, isTrue);
    expect(cat[0].schema[1].required, isTrue);
    expect(cat[1].schema, isEmpty);

    final b = await c.getPlugin('webhook', 'gh hooks');
    expect(seen.last.method, 'GET');
    expect(seen.last.url.toString(), 'https://relay.example/v2/admin/plugins/webhook/gh%20hooks');
    expect(b.configVersion, 4);
    expect(b.secretKeys, ['token_sha256']);
    expect(b.sealed, isTrue);
    expect(b.summary!.hasToken, isTrue);
    expect(b.accounts.single.username, 'u');

    await c.patchPlugin('webhook', 'a/b', const RelayV2PluginPatch(enabled: false, config: {'tag': 'y', 'cors_origins': null}, ifVersion: 4));
    final r = seen.last;
    expect(r.method, 'PATCH');
    expect(r.url.path, '/v2/admin/plugins/webhook/a%2Fb');
    expect(r.headers['Authorization'], 'Bearer tok');
    expect(r.headers['Relay-Access'], 'acc');
    expect(r.headers['Content-Type'], startsWith('application/json'));
    expect(jsonDecode(r.body), {'enabled': false, 'config': {'tag': 'y', 'cors_origins': null}, 'if_version': 4});

    await c.patchPlugin('webhook', 'm', const RelayV2PluginPatch(spaceId: 'personal', boxName: 'inbox'));
    expect(jsonDecode(seen.last.body), {'space_id': 'personal', 'box_name': 'inbox'});

    final acct = await c.upsertPluginAccountPassword('webdav', 'files', scopeKey: 's', username: 'u', password: 'pw', mode: 'rw');
    expect(seen.last.method, 'PUT');
    expect(seen.last.url.path, '/v2/admin/plugins/webdav/files/accounts');
    expect(jsonDecode(seen.last.body), {'scope_key': 's', 'username': 'u', 'password': 'pw', 'mode': 'rw'});
    expect(acct.updatedAt, 9);
  });

  test('old servers decode with defaults and plain-text 404 is unsupported', () async {
    final legacy = RelayV2PluginBinding.fromJson({'id': 'b', 'plugin_id': 'drop', 'mount': 'm', 'enabled': true});
    expect(legacy.configVersion, 0);
    expect(legacy.secretKeys, isEmpty);
    expect(legacy.sealed, isFalse);

    expect(RelayV2Client.isUnsupportedResponse(404, '404 page not found'), isTrue);
    expect(RelayV2Client.isUnsupportedResponse(404, ' {"ok":false,"error":"not found"}'), isFalse);
    expect(RelayV2Client.isUnsupportedResponse(405, '{}'), isTrue);
    expect(RelayV2Client.isUnsupportedResponse(501, ''), isTrue);
    expect(RelayV2Client.isUnsupportedResponse(409, 'conflict'), isFalse);

    var body = '404 page not found\n';
    final c = RelayV2Client(
      baseUrl: 'https://relay.example',
      accessPassword: '',
      token: 'tok',
      httpClient: MockClient((req) async => http.Response(body, 404)),
    );
    Object? err;
    try {
      await c.patchPlugin('drop', 'm', const RelayV2PluginPatch(enabled: true));
    } catch (e) {
      err = e;
    }
    expect(err, isA<RelayV2HttpException>());
    expect(RelayV2Client.isUnsupported(err!), isTrue);
    body = '{"ok":false,"error":"not found"}';
    err = null;
    try {
      await c.getPlugin('drop', 'missing');
    } catch (e) {
      err = e;
    }
    expect((err as RelayV2HttpException).status, 404);
    expect(RelayV2Client.isUnsupported(err), isFalse);
    expect(RelayV2Client.isUnsupported(StateError('x')), isFalse);
  });

  test('me parses device and root admin responses; plain-text 404 is unsupported', () async {
    late http.Request seen;
    var status = 200;
    var body = jsonEncode({
      'ok': true,
      'device': {'id': 'd1', 'name': 'phone', 'public_key': 'pk', 'is_admin': true, 'revoked': false, 'created_at': 5},
    });
    final c = RelayV2Client(
      baseUrl: 'https://relay.example',
      accessPassword: 'pw',
      token: 'tok',
      httpClient: MockClient((req) async {
        seen = req;
        return http.Response(body, status);
      }),
    );
    final me = await c.me();
    expect(seen.method, 'GET');
    expect(seen.url.toString(), 'https://relay.example/v2/me');
    expect(seen.headers['Authorization'], 'Bearer tok');
    expect(me.rootAdmin, isFalse);
    expect(me.device!.id, 'd1');
    expect(me.device!.name, 'phone');
    expect(me.device!.publicKey, 'pk');
    expect(me.device!.isAdmin, isTrue);
    expect(me.device!.createdAt, 5);

    body = '{"ok":true,"root_admin":true}';
    final root = await c.me();
    expect(root.rootAdmin, isTrue);
    expect(root.device, isNull);

    status = 404;
    body = '404 page not found\n';
    Object? err;
    try {
      await c.me();
    } catch (e) {
      err = e;
    }
    expect(RelayV2Client.isUnsupported(err!), isTrue);
  });

  test('opens protocol/v2/sealed-vectors.json and rejects every invalid case', () async {
    final sodium = await SodiumInit.init();
    final v = vectors('sealed-vectors.json');
    final pub = RelayV2Sealed.parseKey(v['recipient_public'] as String),
        priv = RelayV2Sealed.parseKey(v['recipient_private'] as String);
    final sealed = <String, Uint8List>{};
    for (final c in v['valid'] as List) {
      final name = c['name'] as String, bytes = base64Decode(c['sealed_b64'] as String);
      sealed[name] = bytes;
      expect(RelayV2Sealed.isSealed(bytes), isTrue, reason: name);
      final plain = RelayV2Sealed.open(sodium, bytes, pub, priv);
      expect(plain.length, int.parse('${c['plaintext_length']}'), reason: name);
      expect(sha256.convert(plain).toString(), c['plaintext_sha256'], reason: name);
      if (c['plaintext_hex'] != null) expect(hex(plain), c['plaintext_hex'], reason: name);
      if (name == 'two_frames') {
        expect(plain, List.generate(plain.length, (i) => (i * 7 + 3) & 0xff), reason: name);
      }
    }
    expect(sealed.keys, containsAll(['hello', 'empty', 'two_frames']));
    expect(RelayV2Sealed.isSealed(utf8.encode('{"x":1}')), isFalse);

    for (final c in v['invalid'] as List) {
      final base = sealed[c['base']]!;
      final bad = switch (c['op']) {
        'truncate' => Uint8List.sublistView(base, 0, c['length'] as int),
        'append' => Uint8List.fromList([...base, ...unhex(c['hex'] as String)]),
        'flip' => Uint8List.fromList(base)..[c['offset'] as int] ^= 1,
        final op => throw StateError('unknown op $op'),
      };
      expect(() => RelayV2Sealed.open(sodium, bad, pub, priv), throwsFormatException, reason: c['name'] as String);
    }
    final wrongPub = RelayV2Sealed.parseKey(v['wrong_public'] as String),
        wrongPriv = RelayV2Sealed.parseKey(v['wrong_private'] as String);
    expect(() => RelayV2Sealed.open(sodium, sealed['hello']!, wrongPub, wrongPriv), throwsFormatException);

    final other = RelayV2Sealed.generateKeyPair(sodium);
    expect(other.publicKey.length, 64);
    expect(() => RelayV2Sealed.parseKey('abcd'), throwsArgumentError);
  });

  test('multi-frame payloads round-trip and dropping the final frame fails', () async {
    final sodium = await SodiumInit.init();
    final kp = RelayV2Sealed.generateKeyPair(sodium);
    final pub = RelayV2Sealed.parseKey(kp.publicKey), priv = RelayV2Sealed.parseKey(kp.privateKey);
    final plain = Uint8List.fromList(List.generate((64 << 10) * 2 + 5, (i) => i & 0xff));
    final sealed = sealForTest(sodium, pub, plain);
    expect(RelayV2Sealed.open(sodium, sealed, pub, priv), plain);
    final cut = Uint8List.sublistView(sealed, 0, sealed.length - (4 + 5 + 16));
    expect(() => RelayV2Sealed.open(sodium, cut, pub, priv), throwsFormatException);
  });
}
