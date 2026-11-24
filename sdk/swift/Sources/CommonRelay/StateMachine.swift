import Foundation

/// Pipe `msg` topic reserved for optional LAN/direct candidate exchange (§4.9).
public let relayDirectUpgradeTopic = "relay.direct.v1"

/// Pending credential/mutation draft persisted BEFORE issuing network requests.
public struct RelayGroupDraft: Codable, Equatable, Sendable {
    public let draftID: String
    public let op: String // "create" | "join" | "auto_join" | "rotate"
    public let app: String
    public let group: String
    public let device: String
    public let secretKey: String
    public let signSecretKey: String
    public let token: String
    public let inviteID: String
    public let createdAt: Int64

    enum CodingKeys: String, CodingKey {
        case draftID = "draft_id"
        case op, app, group, device
        case secretKey = "secret_key"
        case signSecretKey = "sign_secret_key"
        case token
        case inviteID = "invite_id"
        case createdAt = "created_at"
    }

    public init(
        draftID: String,
        op: String,
        app: String,
        group: String,
        device: String,
        secretKey: String,
        signSecretKey: String,
        token: String,
        inviteID: String = "",
        createdAt: Int64 = Int64(Date().timeIntervalSince1970)
    ) {
        self.draftID = draftID
        self.op = op
        self.app = app
        self.group = group
        self.device = device
        self.secretKey = secretKey
        self.signSecretKey = signSecretKey
        self.token = token
        self.inviteID = inviteID
        self.createdAt = createdAt
    }

    public func encodeJSON() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public static func decodeJSON(_ data: Data) throws -> RelayGroupDraft {
        try JSONDecoder().decode(RelayGroupDraft.self, from: data)
    }
}

/// Callback-driven draft-before-send group state machine so mid-flight crashes
/// never lose freshly generated keys or tokens.
public struct RelayGroupStateMachine<ResultType>: Sendable where ResultType: Sendable {
    public let saveDraft: @Sendable (RelayGroupDraft) async throws -> Void
    public let loadDraft: (@Sendable () async throws -> RelayGroupDraft?)?
    public let commit: @Sendable (RelayGroupDraft, ResultType) async throws -> Void
    public let clearDraft: @Sendable (String) async throws -> Void

    public init(
        saveDraft: @escaping @Sendable (RelayGroupDraft) async throws -> Void,
        loadDraft: (@Sendable () async throws -> RelayGroupDraft?)? = nil,
        commit: @escaping @Sendable (RelayGroupDraft, ResultType) async throws -> Void,
        clearDraft: @escaping @Sendable (String) async throws -> Void
    ) {
        self.saveDraft = saveDraft
        self.loadDraft = loadDraft
        self.commit = commit
        self.clearDraft = clearDraft
    }

    public func pendingDraft() async throws -> RelayGroupDraft? {
        guard let loadDraft else { return nil }
        return try await loadDraft()
    }

    /// Persists `draft` before invoking `action`. If `action` throws, `draft`
    /// remains stored for recovery; on success, `commit` and `clearDraft` run.
    public func execute(
        _ draft: RelayGroupDraft,
        action: @Sendable (RelayGroupDraft) async throws -> ResultType
    ) async throws -> ResultType {
        try await saveDraft(draft)
        let result = try await action(draft)
        try await commit(draft, result)
        try await clearDraft(draft.draftID)
        return result
    }
}

/// Plaintext payload carried inside a §6 encrypted envelope on `relayDirectUpgradeTopic`.
public struct RelayDirectUpgradeMessage: Codable, Equatable, Sendable {
    public let op: String // "offer" | "answer" | "fallback"
    public let session: String
    public let candidates: [String]
    public let nonce: String

    public init(op: String, session: String, candidates: [String] = [], nonce: String = "") {
        self.op = op
        self.session = session
        self.candidates = candidates
        self.nonce = nonce
    }

    public func validate() throws {
        guard op == "offer" || op == "answer" || op == "fallback" else {
            throw RelayError.invalid("invalid direct upgrade op")
        }
        guard !session.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw RelayError.invalid("direct upgrade session is required")
        }
    }

    public func encode() throws -> Data {
        try validate()
        return try JSONEncoder().encode(self)
    }

    public static func decode(_ data: Data) throws -> RelayDirectUpgradeMessage {
        let msg = try JSONDecoder().decode(RelayDirectUpgradeMessage.self, from: data)
        try msg.validate()
        return msg
    }
}
