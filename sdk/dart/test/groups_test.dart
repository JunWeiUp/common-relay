import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' show sha256;
import 'package:test/test.dart';
import 'package:sodium/sodium.dart';
import 'package:common_relay/common_relay.dart';
import 'vectors.dart';

void main() {
  test(
    'shared membership signatures, revocation and rollback rejection',
    () async {
      final sodium = await SodiumInit.init();
      final v = vectors('group-vectors.json');
      final groups = RelayGroups(sodium, v['config'] as Map<String, dynamic>);
      final first = v['initial'] as Map<String, dynamic>,
          added = v['approved'] as Map<String, dynamic>,
          removed = v['removed'] as Map<String, dynamic>;
      expect(groups.member('Mac')['signing_key'], v['manager']['signing_key']);
      groups.verify(v['self_service'] as Map<String,dynamic>, v['manager']['signing_key'] as String);
      groups.verify(first, v['manager']['signing_key'] as String);
      groups.advance(first, added);
      groups.advance(added, removed);
      groups.advance(added,v['renamed'] as Map<String,dynamic>);
      expect(() => groups.advance(added,v['unauthorized_rename'] as Map<String,dynamic>),throwsStateError);
      groups.advance(added, v['left'] as Map<String,dynamic>);
      groups.advance(added, v['disbanded'] as Map<String,dynamic>);
      expect(() => groups.advance(added, v['unauthorized_disband'] as Map<String,dynamic>), throwsStateError);
      expect(() => groups.advance(first, removed), throwsStateError);
      final automatic = v['auto_admission'] as Map<String,dynamic>;
      groups.advance(first,automatic['approved'] as Map<String,dynamic>);
      for(final item in automatic['invalid'] as List) { expect(()=>groups.advance(first,item['entry'] as Map<String,dynamic>),throwsA(anything),reason:item['case'] as String); }
      final strict = v['strict_payload'] as Map<String,dynamic>;
      for(final item in strict['valid'] as List) { groups.advance(added,item['entry'] as Map<String,dynamic>); }
      for(final item in strict['invalid'] as List) { expect(()=>groups.advance(added,item['entry'] as Map<String,dynamic>),throwsA(anything),reason:item['case'] as String); }
      for(final item in strict['invalid_auto'] as List) { expect(()=>groups.advance(first,item['entry'] as Map<String,dynamic>),throwsA(anything),reason:item['case'] as String); }
      expect(
        () => groups.advance(first, {
          ...added,
          'signature': List.filled(64, '00').join(),
        }),
        throwsStateError,
      );
    },
  );

  test('entry_hashes: payload digests, signatures and previous links', () async {
    final sodium = await SodiumInit.init();
    final v = vectors('group-vectors.json');
    final groups = RelayGroups(sodium, v['config'] as Map<String, dynamic>);
    Map<String, dynamic> entry(String path) =>
        path.split('.').fold<dynamic>(v, (node, k) => node[k]) as Map<String, dynamic>;
    Uint8List raw(String path) => base64Decode(entry(path)['payload'] as String);
    final hashes = v['entry_hashes'] as Map<String, dynamic>;
    for (final c in hashes['cases'] as List) {
      final path = c['entry'] as String, why = '$path / ${c['verify_key']}';
      expect(sha256.convert(raw(path)).toString(), c['payload_sha256'], reason: why);
      expect(RelayGroups.digest(raw(path)), c['payload_sha256'], reason: why);
      final ok = () {
        try {
          groups.verify(entry(path), c['verify_key'] as String);
          return true;
        } on StateError {
          return false;
        }
      }();
      expect(ok, c['signature_valid'], reason: why);
    }
    for (final l in hashes['links'] as List) {
      final next = jsonDecode(utf8.decode(raw(l['next'] as String))) as Map<String, dynamic>;
      expect(next['previous'], RelayGroups.digest(raw(l['base'] as String)), reason: '${l['base']} -> ${l['next']}');
    }
  });
}
