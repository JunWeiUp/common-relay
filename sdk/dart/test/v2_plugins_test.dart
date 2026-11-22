import 'dart:convert';
import 'dart:typed_data';
import 'package:common_relay/common_relay.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sodium/sodium.dart';
import 'package:test/test.dart';

// Fixed vectors produced by sdk/go/v2client SealStream (recipient private key = 32 x 0x42).
const vecPublic = '132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472';
final vecPrivate = '42' * 32;
const vecHello =
    '435253318060211cbbbb765d2dcb943d8373a8389ce9e2409001ca7cd5fa9572c3267b305d3593574756b28720e140d0a61e3bc20371a2aa079a321fb808722e208c2d2cb4e3804a2b3f32f1160a1e832e7a55fb08290b6df4e8cd043917b0f2f3c89463000000210ea5b12a2fb9ef63bc511f08e718632e069600737c791c3032ee1bd1dbf961bc9d';
const vecEmpty =
    '43525331d23a619a1d158a1af281e170675d0d63e98c4fb84c8dc1cc4598bea00692183cfac3564174de5cd264f242fd4972beea37f96f1c0901e95d147a63f561235f78d02b9b6fd1f2bc8a1195b015fcd417064dea8fa17a669b86d3bcc4fe6d7d3a230000001024ef6f7ff1b06ef0b51a3ecc2b6e9026';

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

  test('opens crs1 vectors sealed by the Go SDK', () async {
    final sodium = await SodiumInit.init();
    final pub = RelayV2Sealed.parseKey(vecPublic), priv = RelayV2Sealed.parseKey(vecPrivate);
    final hello = unhex(vecHello);
    expect(RelayV2Sealed.isSealed(hello), isTrue);
    expect(RelayV2Sealed.isSealed(utf8.encode('{"x":1}')), isFalse);
    expect(utf8.decode(RelayV2Sealed.open(sodium, hello, pub, priv)), 'hello sealed crs1');
    expect(RelayV2Sealed.open(sodium, unhex(vecEmpty), pub, priv), isEmpty);

    // Truncation, trailing junk and bit flips in key, prefix and frame must fail.
    expect(() => RelayV2Sealed.open(sodium, Uint8List.sublistView(hello, 0, hello.length - 1), pub, priv), throwsFormatException);
    expect(() => RelayV2Sealed.open(sodium, Uint8List.fromList([...hello, 0]), pub, priv), throwsFormatException);
    for (final i in [10, 90, 110, hello.length - 1]) {
      final t = Uint8List.fromList(hello)..[i] ^= 1;
      expect(() => RelayV2Sealed.open(sodium, t, pub, priv), throwsFormatException, reason: 'flip at $i');
    }
    final other = RelayV2Sealed.generateKeyPair(sodium);
    expect(other.publicKey.length, 64);
    expect(() => RelayV2Sealed.open(sodium, hello, RelayV2Sealed.parseKey(other.publicKey), RelayV2Sealed.parseKey(other.privateKey)), throwsFormatException);
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
