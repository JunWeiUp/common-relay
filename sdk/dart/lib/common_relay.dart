library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';
// Pinned sodium native bindings expose init_push before any data record.
import 'package:sodium/src/ffi/bindings/libsodium.ffi.dart' as native;
import 'dart:typed_data';
import 'package:sodium/sodium.dart';
import 'package:http/http.dart' as http;
import 'package:crypto/crypto.dart' as hashes;

part 'src/files.dart';
part 'src/journal.dart';
part 'src/groups.dart';
part 'src/invitation_links.dart';
part 'src/payload.dart';
part 'src/v2_client.dart';
part 'src/v2_pipe.dart';

String hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
Uint8List unhex(String value) {
  if (value.length.isOdd) throw const FormatException('Invalid hex');
  return Uint8List.fromList([for (var i = 0; i < value.length; i += 2) int.parse(value.substring(i, i + 2), radix: 16)]);
}
Uint8List jsonBytes(Object value) => Uint8List.fromList(utf8.encode(jsonEncode(value)));

/// Header carrying the server-wide access password on every `/v2` request (WebSocket, group ledger, enrollment and files).
const relayAccessHeader = 'Relay-Access';

/// Validates an optional server access password: 8-128 printable ASCII characters (0x21-0x7E).
/// The value itself is never included in the error.
String? relayAccessPassword(Object? value) {
  if (value == null) return null;
  if (value is! String || value.length < 8 || value.length > 128 || value.codeUnits.any((c) => c < 0x21 || c > 0x7e)) {
    throw ArgumentError('Relay access password must be 8-128 printable ASCII characters without spaces');
  }
  return value;
}
Map<String, String> _accessHeaders(String? password) => password == null ? const {} : {relayAccessHeader: password};

class RelayIdentity {
  final Sodium sodium;
  final String app, group, device;
  final SecureKey secretKey;
  final Uint8List publicKey;
  final Map<String, Uint8List> trustedPeers;
  RelayIdentity({required this.sodium, required this.app, required this.group, required this.device, required this.secretKey, required this.publicKey, required Map<String, Uint8List> trustedPeers}) : trustedPeers = Map.unmodifiable(trustedPeers);
  List<Object> context(String from, String to, String kind, String id) => [1, app, group, from, to, kind, id];
  Uint8List aad(String from, String to, String kind, String id, int seq) => jsonBytes([...context(from, to, kind, id), seq]);
  String seal(String to, String kind, String id, Map<String, dynamic> value) {
    final peer = trustedPeers[to];
    if (peer == null) throw StateError('Untrusted peer');
    final nonce = sodium.randombytes.buf(24);
    final cipher = sodium.crypto.box.easy(message: jsonBytes({'context': context(device, to, kind, id), 'value': value}), nonce: nonce, publicKey: peer, secretKey: secretKey);
    return base64Encode([...nonce, ...cipher]);
  }
  Map<String, dynamic> open(String from, String kind, String id, String body) {
    final peer = trustedPeers[from];
    final raw = base64Decode(body);
    if (peer == null || raw.length < 40) throw StateError('Untrusted peer or invalid envelope');
    final plain = sodium.crypto.box.openEasy(cipherText: Uint8List.sublistView(raw, 24), nonce: Uint8List.sublistView(raw, 0, 24), publicKey: peer, secretKey: secretKey);
    final parsed = jsonDecode(utf8.decode(plain)) as Map<String, dynamic>;
    if (jsonEncode(parsed['context']) != jsonEncode(context(from, device, kind, id))) throw StateError('Context mismatch');
    return parsed['value'] as Map<String, dynamic>;
  }
}

class RelayEncryptStream implements ffi.Finalizable {
  final SecureKey key;
  final ffi.Pointer<ffi.Void> _state;
  final Uint8List header;
  bool finished = false, _closed = false;
  static final _finalizer = ffi.NativeFinalizer(ffi.Native.addressOf(native.sodium_free));
  RelayEncryptStream._(this.key, this._state, this.header) { _finalizer.attach(this, _state, detach: this); }
  static Future<RelayEncryptStream> create(Sodium sodium) async {
    final key = sodium.crypto.secretStream.keygen();
    final state = native.sodium_malloc(native.crypto_secretstream_xchacha20poly1305_statebytes());
    if (state == ffi.nullptr) { key.dispose(); throw StateError('Allocation failed'); }
    final header = calloc<ffi.UnsignedChar>(24), secret = calloc<ffi.UnsignedChar>(32);
    try {
      secret.cast<ffi.Uint8>().asTypedList(32).setAll(0, key.extractBytes());
      if (native.crypto_secretstream_xchacha20poly1305_init_push(state.cast(), header, secret) != 0) throw StateError('Stream initialization failed');
      return RelayEncryptStream._(key, state, Uint8List.fromList(header.cast<ffi.Uint8>().asTypedList(24)));
    } catch (_) { native.sodium_free(state); key.dispose(); rethrow; }
    finally { native.sodium_memzero(secret.cast(), 32); calloc.free(secret); calloc.free(header); }
  }
  Map<String, dynamic> get descriptor => {'key': hex(key.extractBytes()), 'header': hex(header)};
  Future<Uint8List> push(Uint8List data, Uint8List aad, {bool finalRecord = false}) async {
    if (_closed || finished || data.length > 65519) throw StateError('Invalid stream state');
    final plain = calloc<ffi.UnsignedChar>(data.isEmpty ? 1 : data.length), ad = calloc<ffi.UnsignedChar>(aad.isEmpty ? 1 : aad.length), out = calloc<ffi.UnsignedChar>(data.length + 17);
    try {
      plain.cast<ffi.Uint8>().asTypedList(data.length).setAll(0, data); ad.cast<ffi.Uint8>().asTypedList(aad.length).setAll(0, aad);
      if (native.crypto_secretstream_xchacha20poly1305_push(_state.cast(), out, ffi.nullptr, plain, data.length, ad, aad.length, finalRecord ? 3 : 0) != 0) throw StateError('Encryption failed');
      finished = finalRecord; return Uint8List.fromList(out.cast<ffi.Uint8>().asTypedList(data.length + 17));
    } finally { native.sodium_memzero(plain.cast(), data.length); calloc.free(plain); calloc.free(ad); calloc.free(out); }
  }
  Future<void> close() async { if (_closed) return; _closed = true; _finalizer.detach(this); native.sodium_free(_state); key.dispose(); }
}

class RelayDecryptStream {
  final SecureKey key;
  final StreamController<SecretStreamCipherMessage> _input;
  final StreamIterator<SecretStreamPlainMessage> _output;
  bool finished = false;
  RelayDecryptStream._(this.key, this._input, this._output);
  static RelayDecryptStream create(Sodium sodium, Map<String, dynamic> descriptor) {
    final key = SecureKey.fromList(sodium, unhex(descriptor['key'] as String));
    final input = StreamController<SecretStreamCipherMessage>();
    final output = StreamIterator(sodium.crypto.secretStream.pullEx(cipherStream: input.stream, key: key));
    input.add(SecretStreamCipherMessage(unhex(descriptor['header'] as String)));
    return RelayDecryptStream._(key, input, output);
  }
  Future<Uint8List> pull(Uint8List cipher, Uint8List aad) async {
    if (finished || cipher.length < 17 || cipher.length > 65536) throw StateError('Invalid stream state');
    _input.add(SecretStreamCipherMessage(cipher, additionalData: aad));
    if (!await _output.moveNext()) throw StateError('Decryption stream closed');
    final message = _output.current;
    if (message.tag != SecretStreamMessageTag.message && message.tag != SecretStreamMessageTag.finalPush) throw StateError('Invalid stream tag');
    finished = message.tag == SecretStreamMessageTag.finalPush;
    return message.message;
  }
  Future<void> close() async { await _output.cancel(); unawaited(_input.close()); key.dispose(); }
}
