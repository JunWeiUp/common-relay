part of '../common_relay.dart';

/// Bidirectional E2E-encrypted stream running over Common Relay v2 `/v2/ws` binary frames
/// (`[16-byte streamID][XChaCha20-Poly1305 secretstream chunk]`).
class RelayV2Stream {
  final String id;
  final String peer;
  final RelayIdentity _identity;
  final Future<void> Function(Uint8List frame) _sendFrame;
  final Future<void> Function() _sendCloseEvent;
  final void Function(int credit)? _sendCredit;
  final RelayEncryptStream _tx;
  RelayDecryptStream? _rx;
  int _sendSeq = 0;
  int _recvSeq = 0;
  int _uncreditedRecv = 0;
  Completer<void>? _backpressureWait;
  final _incoming = StreamController<Uint8List>();
  bool _closed = false;

  static const _creditBatch = 16;

  RelayV2Stream._({
    required this.id,
    required this.peer,
    required RelayIdentity identity,
    required RelayEncryptStream tx,
    RelayDecryptStream? rx,
    required Future<void> Function(Uint8List frame) sendFrame,
    required Future<void> Function() sendCloseEvent,
    void Function(int credit)? sendCredit,
  })  : _identity = identity,
        _tx = tx,
        _rx = rx,
        _sendFrame = sendFrame,
        _sendCloseEvent = sendCloseEvent,
        _sendCredit = sendCredit;

  Stream<Uint8List> get data => _incoming.stream;

  void _attachReceiver(RelayDecryptStream rx) {
    _rx = rx;
  }

  void _onCredit(int seq) {
    if (seq == 0) {
      _backpressureWait ??= Completer<void>();
    } else if (seq > 0) {
      final w = _backpressureWait;
      _backpressureWait = null;
      if (w != null && !w.isCompleted) w.complete();
    }
  }

  Future<void> send(Uint8List plain) async {
    if (_closed) throw StateError('v2 stream closed');
    var offset = 0;
    while (offset < plain.length) {
      final wait = _backpressureWait;
      if (wait != null && !wait.isCompleted) {
        await wait.future.timeout(const Duration(milliseconds: 250), onTimeout: () {});
        _backpressureWait = null;
      }
      if (_closed) throw StateError('v2 stream closed');
      final end = (offset + 65519) < plain.length ? offset + 65519 : plain.length;
      final chunk = Uint8List.sublistView(plain, offset, end);
      final aad = _identity.aad(_identity.device, peer, 'stream', id, _sendSeq++);
      final cipher = await _tx.push(chunk, aad);
      final frame = RelayV2Client.encodeStreamFrame(id, cipher);
      await _sendFrame(frame);
      offset = end;
    }
  }

  Future<void> _deliver(Uint8List cipher) async {
    if (_closed || _rx == null) return;
    try {
      final aad = _identity.aad(peer, _identity.device, 'stream', id, _recvSeq++);
      final plain = await _rx!.pull(cipher, aad);
      if (plain.isNotEmpty && !_incoming.isClosed) {
        _incoming.add(plain);
      }
      _uncreditedRecv++;
      if (_uncreditedRecv >= _creditBatch) {
        _uncreditedRecv = 0;
        try {
          _sendCredit?.call(_creditBatch);
        } catch (_) {}
      }
      if (_rx!.finished) {
        await _finishLocal();
      }
    } catch (e, st) {
      if (!_incoming.isClosed) {
        _incoming.addError(e, st);
      }
      await _finishLocal();
    }
  }

  Future<void> _remoteClosed() => _finishLocal();

  Future<void> close() async {
    if (_closed) return;
    try {
      if (!_tx.finished) {
        final aad = _identity.aad(_identity.device, peer, 'stream', id, _sendSeq++);
        final cipher = await _tx.push(Uint8List(0), aad, finalRecord: true);
        final frame = RelayV2Client.encodeStreamFrame(id, cipher);
        await _sendFrame(frame);
      }
    } catch (_) {}
    await _finishLocal();
    await _sendCloseEvent();
  }

  Future<void> _finishLocal() async {
    if (_closed) return;
    _closed = true;
    await _tx.close();
    await _rx?.close();
    if (!_incoming.isClosed) {
      await _incoming.close();
    }
  }
}

/// Common Relay v2 Pipe over `/v2/ws` for Dart/Flutter.
class RelayV2Pipe {
  final RelayV2Client client;
  final String space;
  final RelayIdentity identity;

  WebSocket? _socket;
  StreamSubscription<dynamic>? _sub;
  final _events = StreamController<Map<String, dynamic>>();
  final _streams = <String, RelayV2Stream>{};
  final _pendingAccept = <String, Completer<Map<String, dynamic>>>{};
  final _pendingPresence = <String, Completer<List<String>>>{};
  bool _closed = false;

  RelayV2Pipe({
    required this.client,
    required this.space,
    required this.identity,
  });

  Stream<Map<String, dynamic>> get events => _events.stream;

  Future<void> connect() async {
    final headers = <String, dynamic>{
      'Authorization': 'Bearer ${client.token}',
      'X-Relay-Features': 'stream-credit',
      if (client.accessPassword.isNotEmpty) relayAccessHeader: client.accessPassword,
    };
    final ws = await WebSocket.connect(client.wsUrl, headers: headers);
    ws.pingInterval = const Duration(seconds: 25);
    _socket = ws;
    _closed = false;

    _sub = ws.listen(
      (dynamic raw) {
        if (raw is Uint8List || raw is List<int>) {
          final frame = raw is Uint8List ? raw : Uint8List.fromList(raw as List<int>);
          unawaited(_handleBinary(frame));
        } else if (raw is String) {
          try {
            final ev = jsonDecode(raw) as Map<String, dynamic>;
            unawaited(_handleEvent(ev));
          } catch (_) {}
        }
      },
      onError: (Object err, StackTrace st) {
        unawaited(_cleanupOnDisconnect(err));
        if (!_events.isClosed) _events.addError(err, st);
      },
      onDone: () {
        unawaited(_cleanupOnDisconnect(StateError('v2 pipe closed')));
        if (!_events.isClosed) unawaited(_events.close());
      },
      cancelOnError: false,
    );
  }

  Future<List<String>> peers({Duration timeout = const Duration(seconds: 5)}) async {
    final reqId = hex(identity.sodium.randombytes.buf(8));
    final completer = Completer<List<String>>();
    _pendingPresence[reqId] = completer;
    _sendJson({'type': 'presence', 'space': space, 'id': reqId});
    try {
      return await completer.future.timeout(timeout);
    } finally {
      _pendingPresence.remove(reqId);
    }
  }

  Future<String> sendMessage(
    String to,
    String topic,
    Uint8List plaintext, {
    bool offline = false,
    int? ttlSeconds,
    String? id,
    String kind = 'message',
  }) async {
    final msgId = id ?? hex(identity.sodium.randombytes.buf(12));
    final sealed = identity.seal(to, kind, msgId, {
      'data': base64Encode(plaintext),
    });
    _sendJson({
      'type': 'msg',
      'space': space,
      'id': msgId,
      'to': to,
      'topic': topic,
      'body': sealed,
      if (offline) 'offline': true,
      if (ttlSeconds != null && ttlSeconds > 0) 'ttl': ttlSeconds,
    });
    return msgId;
  }

  /// Sends a `/v2/ws` `ack` for an offline message (or to drop an undecryptable
  /// message per §4.5 after durable local processing / roster verification).
  void ackMessage(String from, String id, {String? spaceId}) {
    _sendJson({
      'type': 'ack',
      'space': spaceId ?? space,
      'from': from,
      'id': id,
    });
  }

  /// Requests the next batch (up to 256) of un-ACKed offline messages for this
  /// Space without reconnecting. Ends with a `msg.pull.done` event.
  String pullOfflineMessages({String? id}) {
    final reqId = id ?? hex(identity.sodium.randombytes.buf(8));
    _sendJson({'type': 'msg.pull', 'space': space, 'id': reqId});
    return reqId;
  }

  /// Grants flow-control credit (`seq` frames, or `0` to pause) for a ready stream.
  void sendStreamCredit(String streamId, int credit) {
    if (credit < 0) throw ArgumentError.value(credit, 'credit', 'must be >= 0');
    _sendJson({
      'type': 'stream.credit',
      'space': space,
      'id': streamId,
      'seq': credit,
    });
  }

  bool isTrustedSender(String deviceId) => identity.trustedPeers.containsKey(deviceId);

  Uint8List openMessage(Map<String, dynamic> event) {
    final from = event['from'] as String? ?? '';
    final id = event['id'] as String? ?? '';
    final body = event['body'] as String? ?? '';
    try {
      final opened = identity.open(from, 'message', id, body);
      return base64Decode(opened['data'] as String);
    } catch (_) {
      final opened = identity.open(from, 'msg', id, body);
      return base64Decode(opened['data'] as String);
    }
  }

  /// Attempts to decrypt a `msg` event without throwing on §4.5 undecryptable
  /// envelopes. Returns `null` if the sender is untrusted or authentication fails.
  Uint8List? tryOpenMessage(Map<String, dynamic> event) {
    try {
      return openMessage(event);
    } catch (_) {
      return null;
    }
  }

  Future<RelayV2Stream> openStream(
    String peer, {
    String topic = 'stream',
    Duration timeout = const Duration(seconds: 15),
  }) async {
    final sid = hex(identity.sodium.randombytes.buf(8));
    final tx = await RelayEncryptStream.create(identity.sodium);
    final sealed = identity.seal(peer, 'stream.open', sid, tx.descriptor);
    final stream = RelayV2Stream._(
      id: sid,
      peer: peer,
      identity: identity,
      tx: tx,
      sendFrame: (frame) async => _sendBinary(frame),
      sendCloseEvent: () => closeStream(sid),
      sendCredit: (n) => sendStreamCredit(sid, n),
    );
    _streams[sid] = stream;
    final completer = Completer<Map<String, dynamic>>();
    _pendingAccept[sid] = completer;
    try {
      _sendJson({
        'type': 'stream.open',
        'space': space,
        'id': sid,
        'to': peer,
        'topic': topic,
        'body': sealed,
      });
      final acc = await completer.future.timeout(timeout);
      final body = acc['body'] as String? ?? '';
      final desc = identity.open(peer, 'stream.accept', sid, body);
      stream._attachReceiver(RelayDecryptStream.create(identity.sodium, desc));
      return stream;
    } catch (_) {
      _pendingAccept.remove(sid);
      _streams.remove(sid);
      await stream._remoteClosed();
      rethrow;
    }
  }

  Future<RelayV2Stream> acceptStream(Map<String, dynamic> event) async {
    final sid = event['id'] as String? ?? '';
    final peer = event['from'] as String? ?? '';
    final body = event['body'] as String? ?? '';
    if (sid.length != 16 || peer.isEmpty || body.isEmpty) {
      throw ArgumentError('invalid stream.open event');
    }
    final remoteDesc = identity.open(peer, 'stream.open', sid, body);
    final rx = RelayDecryptStream.create(identity.sodium, remoteDesc);
    final tx = await RelayEncryptStream.create(identity.sodium);
    final sealed = identity.seal(peer, 'stream.accept', sid, tx.descriptor);
    final stream = RelayV2Stream._(
      id: sid,
      peer: peer,
      identity: identity,
      tx: tx,
      rx: rx,
      sendFrame: (frame) async => _sendBinary(frame),
      sendCloseEvent: () => closeStream(sid),
      sendCredit: (n) => sendStreamCredit(sid, n),
    );
    _streams[sid] = stream;
    _sendJson({
      'type': 'stream.accept',
      'space': space,
      'id': sid,
      'body': sealed,
    });
    return stream;
  }

  Future<void> rejectStream(Map<String, dynamic> event) async {
    final sid = event['id'] as String?;
    if (sid != null && sid.isNotEmpty) {
      await closeStream(sid);
    }
  }

  Future<void> closeStream(String sid) async {
    _streams.remove(sid);
    try {
      _sendJson({'type': 'stream.close', 'space': space, 'id': sid});
    } catch (_) {}
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _sub?.cancel();
    _sub = null;
    await _socket?.close();
    _socket = null;
    await _cleanupOnDisconnect(StateError('v2 pipe closed'));
    if (!_events.isClosed) await _events.close();
  }

  void _sendJson(Map<String, dynamic> obj) {
    final ws = _socket;
    if (ws == null) throw StateError('v2 pipe not connected');
    ws.add(jsonEncode(obj));
  }

  void _sendBinary(Uint8List frame) {
    final ws = _socket;
    if (ws == null) throw StateError('v2 pipe not connected');
    ws.add(frame);
  }

  Future<void> _handleBinary(Uint8List frame) async {
    try {
      final decoded = RelayV2Client.decodeStreamFrame(frame);
      final stream = _streams[decoded.streamId];
      if (stream != null) {
        await stream._deliver(decoded.payload);
      }
    } catch (_) {}
  }

  Future<void> _handleEvent(Map<String, dynamic> ev) async {
    switch (ev['type']) {
      case 'presence':
        final reqId = ev['id'] as String?;
        if (reqId != null && _pendingPresence.containsKey(reqId)) {
          final c = _pendingPresence.remove(reqId)!;
          final peers = (ev['peers'] as List? ?? const []).map((e) => e.toString()).toList();
          if (!c.isCompleted) c.complete(peers);
          return;
        }
        if (!_events.isClosed) _events.add(ev);
        return;
      case 'stream.accept':
        final sid = ev['id'] as String?;
        if (sid != null && _pendingAccept.containsKey(sid)) {
          final c = _pendingAccept.remove(sid)!;
          if (!c.isCompleted) c.complete(ev);
        }
        return;
      case 'stream.credit':
        final sid = ev['id'] as String?;
        final seq = (ev['seq'] as num?)?.toInt() ?? 0;
        if (sid != null) {
          _streams[sid]?._onCredit(seq);
        }
        return;
      case 'stream.close':
        final sid = ev['id'] as String?;
        if (sid != null) {
          final c = _pendingAccept.remove(sid);
          if (c != null && !c.isCompleted) c.completeError(StateError('stream closed'));
          final st = _streams.remove(sid);
          if (st != null) await st._remoteClosed();
        }
        return;
      case 'error':
        final id = ev['id'] as String?;
        if (id != null && _pendingAccept.containsKey(id)) {
          final c = _pendingAccept.remove(id)!;
          if (!c.isCompleted) c.completeError(StateError('stream error: ${ev['code'] ?? ''}'));
          return;
        }
        if (id != null && _pendingPresence.containsKey(id)) {
          final c = _pendingPresence.remove(id)!;
          if (!c.isCompleted) c.completeError(StateError('presence error: ${ev['code'] ?? ''}'));
          return;
        }
        if (!_events.isClosed) _events.add(ev);
        return;
      default:
        if (!_events.isClosed) _events.add(ev);
    }
  }

  Future<void> _cleanupOnDisconnect(Object error) async {
    for (final c in _pendingAccept.values) {
      if (!c.isCompleted) c.completeError(error);
    }
    _pendingAccept.clear();
    for (final c in _pendingPresence.values) {
      if (!c.isCompleted) c.completeError(error);
    }
    _pendingPresence.clear();
    final active = _streams.values.toList();
    _streams.clear();
    for (final st in active) {
      await st._remoteClosed();
    }
  }
}
