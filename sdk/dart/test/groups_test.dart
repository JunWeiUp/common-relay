import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';
import 'package:sodium/sodium.dart';
import 'package:common_relay/common_relay.dart';

void main() {
  test(
    'shared membership signatures, revocation and rollback rejection',
    () async {
      final sodium = await SodiumInit.init();
      final v =
          jsonDecode(
                File('../../protocol/group-vectors.json').readAsStringSync(),
              )
              as Map<String, dynamic>;
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
      expect(
        () => groups.advance(first, {
          ...added,
          'signature': List.filled(64, '00').join(),
        }),
        throwsStateError,
      );
    },
  );
}
