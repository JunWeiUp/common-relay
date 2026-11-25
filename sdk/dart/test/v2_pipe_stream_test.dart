import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:common_relay/common_relay.dart';
import 'package:sodium/sodium.dart';
import 'package:test/test.dart';

Future<({RelayIdentity alice, RelayIdentity bob, void Function() dispose})> _pair() async {
  final sodium = await SodiumInit.init();
  final akp = sodium.crypto.box.keyPair();
  final bkp = sodium.crypto.box.keyPair();
  final alice = RelayIdentity(
    sodium: sodium,
    app: 'clipy',
    group: 'grp',
    device: 'alice',
    secretKey: akp.secretKey,
    publicKey: akp.publicKey,
    trustedPeers: {'bob': bkp.publicKey},
  );
  final bob = RelayIdentity(
    sodium: sodium,
    app: 'clipy',
    group: 'grp',
    device: 'bob',
    secretKey: bkp.secretKey,
    publicKey: bkp.publicKey,
    trustedPeers: {'alice': akp.publicKey},
  );
  return (
    alice: alice,
    bob: bob,
    dispose: () {
      akp.secretKey.dispose();
      bkp.secretKey.dispose();
    },
  );
}

void main() {
  test('RelayV2Stream serializes burst binary frames and buffers pre-attach frames', () async {
    final p = await _pair();
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final sockets = <String, WebSocket>{};
    final streamPeers = <String, (String, String)>{};
    final closedStreams = <String>[];

    server.listen((req) async {
      final auth = req.headers.value('authorization') ?? '';
      final dev = auth.replaceFirst('Bearer ', '');
      final ws = await WebSocketTransformer.upgrade(req);
      sockets[dev] = ws;
      ws.listen((raw) {
        if (raw is Uint8List || raw is List<int>) {
          final bytes = raw is Uint8List ? raw : Uint8List.fromList(raw as List<int>);
          final sid = utf8.decode(bytes.sublist(0, 16));
          final pair = streamPeers[sid];
          if (pair == null) return;
          final target = pair.$1 == dev ? pair.$2 : pair.$1;
          sockets[target]?.add(bytes);
          return;
        }
        final ev = jsonDecode(raw as String) as Map<String, dynamic>;
        final type = ev['type'] as String?;
        if (type == 'stream.open') {
          final sid = ev['id'] as String;
          final to = ev['to'] as String;
          streamPeers[sid] = (dev, to);
          sockets[to]?.add(jsonEncode({...ev, 'from': dev}));
        } else if (type == 'stream.accept') {
          final sid = ev['id'] as String;
          final pair = streamPeers[sid];
          if (pair == null) return;
          final target = pair.$1 == dev ? pair.$2 : pair.$1;
          sockets[target]?.add(jsonEncode({...ev, 'from': dev}));
        } else if (type == 'stream.close') {
          final sid = ev['id'] as String;
          closedStreams.add('$dev:$sid');
          final pair = streamPeers.remove(sid);
          if (pair == null) return;
          final target = pair.$1 == dev ? pair.$2 : pair.$1;
          sockets[target]?.add(jsonEncode({...ev, 'from': dev}));
        }
      });
    });

    final baseUrl = 'http://127.0.0.1:${server.port}';
    final ca = RelayV2Client(baseUrl: baseUrl, accessPassword: 'password123', token: 'alice', allowLocal: true);
    final cb = RelayV2Client(baseUrl: baseUrl, accessPassword: 'password123', token: 'bob', allowLocal: true);
    final pipeA = RelayV2Pipe(client: ca, space: 'grp', identity: p.alice);
    final pipeB = RelayV2Pipe(client: cb, space: 'grp', identity: p.bob);

    try {
      await pipeA.connect();
      await pipeB.connect();

      const burstCount = 60;
      final received = <String>[];
      var acceptCount = 0;
      final bobAccepted1 = Completer<RelayV2Stream>();
      final bobAccepted2 = Completer<RelayV2Stream>();

      final subB = pipeB.events.listen((ev) async {
        if (ev['type'] == 'stream.open') {
          acceptCount++;
          final s = await pipeB.acceptStream(ev);
          if (acceptCount == 1) {
            // Immediately burst 60 frames right after stream.accept (also exercises pre-attach buffering on Alice).
            for (var i = 0; i < burstCount; i++) {
              await s.send(Uint8List.fromList(utf8.encode('frame-$i')));
            }
            bobAccepted1.complete(s);
          } else {
            bobAccepted2.complete(s);
          }
        }
      });

      final streamA = await pipeA.openStream('bob', topic: 'clipy.sync');
      final done = Completer<void>();
      final subA = streamA.data.listen((chunk) {
        received.add(utf8.decode(chunk));
        if (received.length == burstCount && !done.isCompleted) {
          done.complete();
        }
      }, onError: (Object err, StackTrace st) {
        if (!done.isCompleted) done.completeError(err, st);
      });

      await done.future.timeout(const Duration(seconds: 5));
      expect(received, List.generate(burstCount, (i) => 'frame-$i'));

      final streamB = await bobAccepted1.future;
      final bobDone = Completer<void>();
      final subBData = streamB.data.listen((_) {}, onDone: () {
        if (!bobDone.isCompleted) bobDone.complete();
      });
      await subA.cancel();
      await streamA.close();
      await bobDone.future.timeout(const Duration(seconds: 3));
      await subBData.cancel();

      // Second stream: corrupt frame -> peer must receive stream.close immediately.
      closedStreams.clear();
      final streamA2 = await pipeA.openStream('bob', topic: 'clipy.sync');
      final streamB2 = await bobAccepted2.future;
      final aErr = Completer<Object>();
      final bClosed = Completer<void>();
      final subA2 = streamA2.data.listen((_) {}, onError: (Object e) {
        if (!aErr.isCompleted) aErr.complete(e);
      });
      final subB2Data = streamB2.data.listen((_) {}, onDone: () {
        if (!bClosed.isCompleted) bClosed.complete();
      });

      // Inject garbage ciphertext addressed to Alice's streamA2.
      final bad = RelayV2Client.encodeStreamFrame(streamA2.id, Uint8List(32));
      sockets['alice']!.add(bad);

      await aErr.future.timeout(const Duration(seconds: 3));
      await bClosed.future.timeout(const Duration(seconds: 3));
      expect(closedStreams, contains('alice:${streamA2.id}'));

      await subA2.cancel();
      await subB2Data.cancel();
      await subB.cancel();
    } finally {
      await pipeA.close();
      await pipeB.close();
      ca.close();
      cb.close();
      await server.close(force: true);
      p.dispose();
    }
  });
}
