import 'dart:io';
import 'package:crypto/crypto.dart' as hashes;
import 'dart:convert';
import 'package:test/test.dart';
import 'package:sodium/sodium.dart';
import 'package:common_relay/common_relay.dart';

// Runs the signed group ledger against a real v2 relay built by
// `go build -o build/common-relay ./cmd/common-relay` (skipped when absent).
void main() {
  final binary = File('../../build/common-relay').absolute.path;
  const access = 'dart-loopback-access-1';
  late Sodium sodium;
  late Process server;
  late String url;
  late Directory dir;

  setUpAll(() async {
    sodium = await SodiumInit.init();
    if (!File(binary).existsSync()) return;
    dir = await Directory.systemTemp.createTemp('relay-dart-groups-');
    final socket = await ServerSocket.bind('127.0.0.1', 0);
    final port = socket.port;
    await socket.close();
    File('${dir.path}/access').writeAsStringSync('${hashes.sha256.convert(utf8.encode(access))}\n');
    File('${dir.path}/admin').writeAsStringSync('${hashes.sha256.convert(utf8.encode('test-v2-admin-secret'))}\n');
    server = await Process.start(binary, ['serve', '--data', '${dir.path}/data', '--listen', '127.0.0.1:$port', '--disk-reserve', '0', '--self-service-apps', 'example', '--access-password-file', '${dir.path}/access', '--v2-admin-hash-file', '${dir.path}/admin']);
    server.stdout.drain<void>();
    server.stderr.drain<void>();
    for (var i = 0;; i++) {
      try {
        final c = HttpClient();
        final r = await (await c.getUrl(Uri.parse('http://127.0.0.1:$port/healthz'))).close();
        await r.drain<void>();
        c.close();
        break;
      } catch (_) {
        if (i > 200) rethrow;
        await Future<void>.delayed(const Duration(milliseconds: 25));
      }
    }
    url = 'ws://127.0.0.1:$port/v2/ws';
  });
  tearDownAll(() async {
    if (!File(binary).existsSync()) return;
    server.kill();
    await server.exitCode;
    await dir.delete(recursive: true);
  });

  Map<String, dynamic> device(String id, {bool password = true}) => {
        'url': url, 'app': 'example', 'device': id,
        'secret_key': hex(sodium.crypto.box.keyPair().secretKey.extractBytes()),
        if (password) 'password': access,
      };

  test('create, invite (manual + auto short link), approve, rename, exit over /v2', () async {
    final owner = RelayGroups(sodium, device('one'), allowLocalTest: true);
    owner.prepareCreate('Devices', 'One');
    await owner.create();
    expect((await owner.refresh())['state']['name'], 'Devices');

    final manual = await owner.invite();
    final peer = RelayGroups(sodium, {...device('peer-manual'), 'group': owner.config['group']}, allowLocalTest: true);
    await peer.join(manual, 'Peer');
    final request = await owner.pending(manual);
    expect(request, isNotNull);
    await owner.approve(manual, request!);
    expect(await peer.finishJoin(), isTrue);
    await peer.rename('peer-manual', 'New name');
    await peer.prepareExit();
    await peer.exit();

    final auto = await owner.invite(mode: 'auto', compact: true);
    final link = auto['short_link'] as String;
    expect(link, contains('/v2/i/'));
    final fresh = RelayGroups(sodium, {...device('peer-auto', password: false), 'group': owner.config['group']}, allowLocalTest: true);
    final resolved = await fresh.resolveInvitation(link);
    expect(resolved['url'], url);
    await fresh.join(resolved, 'Auto');
    expect(await fresh.finishJoin(), isTrue);
    expect(fresh.config['password'], access);
    expect((await owner.refresh())['state']['members'].map((m) => m['device']), contains('peer-auto'));

    await owner.prepareExit(disband: true);
    await owner.exit();
  }, skip: File(binary).existsSync() ? false : 'prebuilt relay unavailable (build/common-relay)');
}
