part of '../common_relay.dart';

/// Pipe `msg` topic reserved for optional LAN/direct candidate exchange (§4.9).
const directUpgradeTopic = 'relay.direct.v1';

/// Pending credential/mutation draft persisted BEFORE issuing network requests.
class GroupDraft {
  final String draftId;
  final String op; // "create" | "join" | "auto_join" | "rotate"
  final String app;
  final String group;
  final String device;
  final String secretKey;
  final String signSecretKey;
  final String token;
  final String inviteId;
  final int createdAt;

  GroupDraft({
    required this.draftId,
    required this.op,
    required this.app,
    required this.group,
    required this.device,
    required this.secretKey,
    required this.signSecretKey,
    required this.token,
    this.inviteId = '',
    int? createdAt,
  }) : createdAt = createdAt ?? DateTime.now().millisecondsSinceEpoch ~/ 1000;

  Map<String, dynamic> toJson() => {
        'draft_id': draftId,
        'op': op,
        'app': app,
        'group': group,
        'device': device,
        'secret_key': secretKey,
        'sign_secret_key': signSecretKey,
        'token': token,
        if (inviteId.isNotEmpty) 'invite_id': inviteId,
        'created_at': createdAt,
      };

  String encode() => jsonEncode(toJson());

  factory GroupDraft.decode(String raw) {
    final m = jsonDecode(raw) as Map<String, dynamic>;
    return GroupDraft(
      draftId: m['draft_id'] as String,
      op: m['op'] as String,
      app: m['app'] as String,
      group: m['group'] as String,
      device: m['device'] as String,
      secretKey: m['secret_key'] as String,
      signSecretKey: m['sign_secret_key'] as String,
      token: m['token'] as String,
      inviteId: m['invite_id'] as String? ?? '',
      createdAt: (m['created_at'] as num?)?.toInt() ?? 0,
    );
  }
}

/// Callback-driven draft-before-send group state machine.
class GroupStateMachine<T> {
  final FutureOr<void> Function(GroupDraft draft) saveDraft;
  final FutureOr<GroupDraft?> Function()? loadDraft;
  final FutureOr<void> Function(GroupDraft draft, T result) commit;
  final FutureOr<void> Function(String draftId) clearDraft;

  GroupStateMachine({
    required this.saveDraft,
    required this.commit,
    required this.clearDraft,
    this.loadDraft,
  });

  Future<GroupDraft?> pendingDraft() async {
    final fn = loadDraft;
    return fn == null ? null : await fn();
  }

  /// Persists [draft] before invoking [action]. If [action] throws, the draft
  /// stays persisted for recovery; on success, [commit] and [clearDraft] run.
  Future<T> execute(GroupDraft draft, Future<T> Function(GroupDraft draft) action) async {
    await saveDraft(draft);
    final result = await action(draft);
    await commit(draft, result);
    await clearDraft(draft.draftId);
    return result;
  }
}

/// Plaintext payload carried inside a §6 encrypted envelope on [directUpgradeTopic].
class DirectUpgradeMessage {
  final String op; // "offer" | "answer" | "fallback"
  final String session;
  final List<String> candidates;
  final String nonce;

  const DirectUpgradeMessage({
    required this.op,
    required this.session,
    this.candidates = const [],
    this.nonce = '',
  });

  void validate() {
    if (op != 'offer' && op != 'answer' && op != 'fallback') {
      throw ArgumentError('invalid direct upgrade op: $op');
    }
    if (session.trim().isEmpty) {
      throw ArgumentError('direct upgrade session is required');
    }
  }

  Uint8List encode() {
    validate();
    return jsonBytes({
      'op': op,
      'session': session,
      if (candidates.isNotEmpty) 'candidates': candidates,
      if (nonce.isNotEmpty) 'nonce': nonce,
    });
  }

  factory DirectUpgradeMessage.decode(Uint8List raw) {
    final m = jsonDecode(utf8.decode(raw)) as Map<String, dynamic>;
    final msg = DirectUpgradeMessage(
      op: m['op'] as String? ?? '',
      session: m['session'] as String? ?? '',
      candidates: (m['candidates'] as List? ?? const []).map((e) => e.toString()).toList(),
      nonce: m['nonce'] as String? ?? '',
    );
    msg.validate();
    return msg;
  }
}
