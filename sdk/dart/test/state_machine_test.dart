import 'dart:typed_data';
import 'package:common_relay/common_relay.dart';
import 'package:test/test.dart';

void main() {
  test('GroupStateMachine persists draft before network and clears after commit', () async {
    final trace = <String>[];
    String? storedDraft;
    int? committed;

    final sm = GroupStateMachine<int>(
      saveDraft: (d) {
        trace.add('save');
        storedDraft = d.encode();
      },
      loadDraft: () => storedDraft == null ? null : GroupDraft.decode(storedDraft!),
      commit: (d, rev) {
        trace.add('commit');
        committed = rev;
      },
      clearDraft: (_) {
        trace.add('clear');
        storedDraft = null;
      },
    );

    final draft = GroupDraft(
      draftId: 'd1',
      op: 'create',
      app: 'clipy',
      group: 'g1',
      device: 'mac',
      secretKey: '00' * 32,
      signSecretKey: '11' * 32,
      token: 'a' * 64,
    );

    await expectLater(
      sm.execute(draft, (_) async => throw StateError('network down')),
      throwsStateError,
    );
    expect((await sm.pendingDraft())?.draftId, 'd1');
    expect(committed, isNull);

    final rev = await sm.execute(draft, (_) async => 2);
    expect(rev, 2);
    expect(await sm.pendingDraft(), isNull);
    expect(committed, 2);
    expect(trace, ['save', 'save', 'commit', 'clear']);
  });

  test('DirectUpgradeMessage encode/decode roundtrip', () {
    expect(directUpgradeTopic, 'relay.direct.v1');
    const msg = DirectUpgradeMessage(
      op: 'offer',
      session: 's1',
      candidates: ['192.168.1.2:47899'],
      nonce: 'beef',
    );
    final decoded = DirectUpgradeMessage.decode(msg.encode());
    expect(decoded.op, msg.op);
    expect(decoded.session, msg.session);
    expect(decoded.candidates, msg.candidates);
    expect(decoded.nonce, msg.nonce);
    expect(() => const DirectUpgradeMessage(op: 'bad', session: 's1').encode(), throwsArgumentError);
    expect(() => DirectUpgradeMessage.decode(Uint8List.fromList('{"op":"offer"}'.codeUnits)), throwsArgumentError);
  });
}
