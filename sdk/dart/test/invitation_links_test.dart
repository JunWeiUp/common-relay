import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' show sha256;
import 'package:test/test.dart';
import 'package:sodium/sodium.dart';
import 'package:common_relay/common_relay.dart';
import 'vectors.dart';

void main() {
  test('shared compact invitation encryption and tamper rejection', () async {
    final sodium = await SodiumInit.init();
    final v = vectors('invitation-link-vectors.json');
    final key = unhex(v['key'] as String), nonce = unhex(v['nonce'] as String);
    final packet = v['packet'] as String, link = v['link'] as String;
    final inv = v['invitation'] as Map<String, dynamic>;

    // Packet: opens to the invitation, sealed bytes are exactly packet_plaintext,
    // and deterministic sealing with key + nonce reproduces the packet.
    expect(RelayInvitationLinks.open(sodium, packet, key), inv);
    final raw = base64Decode(packet);
    final plain = sodium.crypto.secretBox.openEasy(
      cipherText: raw.sublist(24),
      nonce: raw.sublist(0, 24),
      key: SecureKey.fromList(sodium, key),
    );
    expect(utf8.decode(plain), v['packet_plaintext']);
    expect(RelayInvitationLinks.seal(sodium, inv, key, nonce), packet);
    expect(() => RelayInvitationLinks.open(sodium, packet, Uint8List(32)), throwsA(anything));

    // Read token and its server-side hash.
    final token = RelayInvitationLinks.readToken(key);
    expect(token, v['read_token']);
    expect(sha256.convert(utf8.encode(token)).toString(), v['read_hash']);
    expect(RelayV2Client.hashSecret(token), v['read_hash']);

    // Links with and without the access password.
    expect(RelayInvitationLinks.make(inv, key), link);
    expect(link.length, int.parse('${v['link_length']}'));
    final parsedLink = RelayInvitationLinks.parse(link);
    expect(parsedLink.url, inv['url']);
    expect(parsedLink.key, key);
    expect(parsedLink.password, isNull);
    final withPassword = v['link_with_password'] as String, access = v['access_password'] as String;
    expect(RelayInvitationLinks.make(inv, key, password: access), withPassword);
    final parsed = RelayInvitationLinks.parse(withPassword);
    expect(parsed.password, access);
    expect(parsed.key, key);
    expect(parsed.url, inv['url']);

    for (final suffix in v['invalid_link_suffixes'] as List) {
      expect(() => RelayInvitationLinks.parse('$link$suffix'), throwsA(anything), reason: suffix as String);
    }
    for (final bad in v['invalid_links'] as List) {
      expect(() => RelayInvitationLinks.parse(bad as String), throwsA(anything), reason: bad);
    }
  });
}
