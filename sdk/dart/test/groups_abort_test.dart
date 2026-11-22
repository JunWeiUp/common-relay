import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';
import 'package:sodium/sodium.dart';
import 'package:common_relay/common_relay.dart';

void main() {
  late Sodium sodium;
  late HttpServer server;
  var hits = 0;
  final started = <Completer<void>>[];
  setUpAll(() async => sodium = await SodiumInit.init());
  setUp(() async {
    hits = 0;
    started.clear();
    server = await HttpServer.bind('127.0.0.1', 0);
    server.listen((r) {
      hits++;
      for (final c in started) {
        if (!c.isCompleted) c.complete();
      }
      // Never answer: only an abort can finish the request.
    });
  });
  tearDown(() => server.close(force: true));
  String ws() => 'ws://127.0.0.1:${server.port}/v2/ws';

  test('abort trigger stops an in-flight group request', () async {
    final groups = RelayGroups(sodium, {'url': ws(), 'app': 'test', 'device': 'test'}, allowLocalTest: true);
    final abort = Completer<void>(), seen = Completer<void>();
    started.add(seen);
    final request = groups.withAbort(abort.future).call('GET', '/group');
    await seen.future;
    abort.complete();
    await expectLater(request.timeout(const Duration(seconds: 1)), throwsA(isA<http.RequestAbortedException>()));
  });

  test('aborted invitation resolution never contacts the relay', () async {
    final groups = RelayGroups(sodium, {'url': ws(), 'app': 'example'}, allowLocalTest: true);
    final link = RelayInvitationLinks.make({'url': ws(), 'id': 'a' * 32}, Uint8List(32));
    await expectLater(groups.withAbort(Future<void>.value()).resolveInvitation(link), throwsA(isA<http.RequestAbortedException>()));
    expect(hits, 0);
  });
}
