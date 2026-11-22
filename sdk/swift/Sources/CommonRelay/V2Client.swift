import Foundation
import CryptoKit
import Clibsodium

/// Common Relay v2 client for Swift (tailored for SyncApp macOS/iOS).
///
/// Design priorities:
///   - Single shared URLSession (zero session leak, low resident memory)
///   - `[16-byte streamID][chunk]` zero-disk binary stream framing for 512 MiB folder transfers
///   - `Box(ephemeral)` offline transfer fallback + `Box(object)` CAS support
///   - SyncApp 3-tier transfer routing helper (LAN -> Pipe stream -> Box ephemeral)
public enum RelayV2Error: Error, Equatable {
    case invalidURL
    case insecureTransport
    case invalidStreamID
    case shortBinaryFrame
    case httpStatus(Int)
    /// Non-2xx answer from the admin plugin API, with the trimmed response body.
    case api(status: Int, body: String)
    case invalidKey
    case sealedCorrupt

    /// True when the server predates an endpoint (e.g. PATCH /v2/admin/plugins/{id}/{mount}):
    /// it answers 405/501, or a plain-text (non-JSON) 404. Callers can fall back to the older PUT API.
    public var isUnsupported: Bool {
        switch self {
        case let .api(status, body): return RelayV2Error.isUnsupported(status: status, body: body)
        case let .httpStatus(status): return status == 405 || status == 501
        default: return false
        }
    }

    public static func isUnsupported(status: Int, body: String) -> Bool {
        status == 405 || status == 501
            || (status == 404 && !body.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{"))
    }
}

public enum RelayV2Route: Equatable {
    case lanDirect
    case pipeStream
    case boxEphemeral
}

public struct RelayV2BoxItem: Codable, Equatable {
    public let id: String
    public let spaceID: String
    public let boxName: String
    public let seq: Int64
    public let sender: String
    public let size: Int64
    public let sha256: String
    public let contentType: String
    public let metaJSON: String
    public let expiresAt: Int64
    public let createdAt: Int64

    enum CodingKeys: String, CodingKey {
        case id, seq, sender, size, sha256
        case spaceID = "space_id"
        case boxName = "box_name"
        case contentType = "content_type"
        case metaJSON = "meta_json"
        case expiresAt = "expires_at"
        case createdAt = "created_at"
    }
}

public struct RelayV2PipeEvent: Codable, Equatable {
    public let type: String
    public let space: String?
    public let id: String?
    public let from: String?
    public let to: String?
    public let topic: String?
    public let box: String?
    public let event: String?
    public let ref: String?
    public let seq: Int64?
    public let body: String?
    public let peers: [String]?
}

/// Minimal JSON value for plugin config patches; `.null` deletes the key server-side.
public enum RelayV2JSONValue: Codable, Equatable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([RelayV2JSONValue])
    case object([String: RelayV2JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(Int64.self) { self = .int(v) }
        else if let v = try? c.decode(Double.self) { self = .double(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([RelayV2JSONValue].self) { self = .array(v) }
        else { self = .object(try c.decode([String: RelayV2JSONValue].self)) }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case let .bool(v): try c.encode(v)
        case let .int(v): try c.encode(v)
        case let .double(v): try c.encode(v)
        case let .string(v): try c.encode(v)
        case let .array(v): try c.encode(v)
        case let .object(v): try c.encode(v)
        }
    }
}

public struct RelayV2PluginBindingSummary: Codable, Equatable {
    public let targetDevice: String?
    public let targetOnline: Bool?
    public let publicBase: String?
    public let tag: String?
    public let hasHMAC: Bool?
    public let hasToken: Bool?
    public let corsOrigins: [String]?

    enum CodingKeys: String, CodingKey {
        case tag
        case targetDevice = "target_device"
        case targetOnline = "target_online"
        case publicBase = "public_base"
        case hasHMAC = "has_hmac"
        case hasToken = "has_token"
        case corsOrigins = "cors_origins"
    }
}

public struct RelayV2PluginAccountView: Codable, Equatable {
    public let scopeKey: String
    public let username: String
    public let mode: String

    enum CodingKeys: String, CodingKey {
        case username, mode
        case scopeKey = "scope_key"
    }
}

public struct RelayV2PluginBinding: Codable, Equatable {
    public let id: String
    public let pluginID: String
    public let mount: String
    public let spaceID: String
    public let boxName: String
    public let configJSON: String
    public let enabled: Bool
    public let updatedAt: Int64
    public let summary: RelayV2PluginBindingSummary?
    public let accounts: [RelayV2PluginAccountView]?
    /// Increments on every change; pass as `ifVersion` for optimistic concurrency. 0 on older servers.
    public let configVersion: Int64
    /// Write-only secret keys currently set (values are never returned).
    public let secretKeys: [String]
    /// Bridged payloads are sealed (crs1) to the binding's seal_public_key.
    public let sealed: Bool

    enum CodingKeys: String, CodingKey {
        case id, mount, enabled, summary, accounts, sealed
        case pluginID = "plugin_id"
        case spaceID = "space_id"
        case boxName = "box_name"
        case configJSON = "config_json"
        case updatedAt = "updated_at"
        case configVersion = "config_version"
        case secretKeys = "secret_keys"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? ""
        pluginID = try c.decodeIfPresent(String.self, forKey: .pluginID) ?? ""
        mount = try c.decodeIfPresent(String.self, forKey: .mount) ?? ""
        spaceID = try c.decodeIfPresent(String.self, forKey: .spaceID) ?? ""
        boxName = try c.decodeIfPresent(String.self, forKey: .boxName) ?? ""
        configJSON = try c.decodeIfPresent(String.self, forKey: .configJSON) ?? "{}"
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        updatedAt = try c.decodeIfPresent(Int64.self, forKey: .updatedAt) ?? 0
        summary = try c.decodeIfPresent(RelayV2PluginBindingSummary.self, forKey: .summary)
        accounts = try c.decodeIfPresent([RelayV2PluginAccountView].self, forKey: .accounts)
        configVersion = try c.decodeIfPresent(Int64.self, forKey: .configVersion) ?? 0
        secretKeys = try c.decodeIfPresent([String].self, forKey: .secretKeys) ?? []
        sealed = try c.decodeIfPresent(Bool.self, forKey: .sealed) ?? false
    }
}

/// One config key a plugin accepts.
public struct RelayV2PluginFieldSpec: Codable, Equatable {
    public let key: String
    public let type: String
    public let description: String?
    public let secret: Bool?
    public let required: Bool?
}

/// A registered plugin with its config schema (nil on servers that predate schemas).
public struct RelayV2PluginInfo: Codable, Equatable {
    public let id: String
    public let requiredTrust: String
    public let schema: [RelayV2PluginFieldSpec]?

    enum CodingKeys: String, CodingKey {
        case id, schema
        case requiredTrust = "required_trust"
    }
}

/// Partial binding update. nil fields are unchanged; a config entry of `.null` deletes that key.
/// Secret keys are write-only: send a plaintext "token" to rotate a Bearer token (hashed server-side).
public struct RelayV2PluginPatch: Encodable, Equatable {
    public var spaceID: String?
    public var boxName: String?
    public var enabled: Bool?
    public var config: [String: RelayV2JSONValue]?
    /// When > 0 the server rejects the patch with 409 unless it equals the stored config_version.
    public var ifVersion: Int64

    public init(spaceID: String? = nil, boxName: String? = nil, enabled: Bool? = nil, config: [String: RelayV2JSONValue]? = nil, ifVersion: Int64 = 0) {
        self.spaceID = spaceID; self.boxName = boxName; self.enabled = enabled; self.config = config; self.ifVersion = ifVersion
    }

    enum CodingKeys: String, CodingKey {
        case enabled, config
        case spaceID = "space_id"
        case boxName = "box_name"
        case ifVersion = "if_version"
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(spaceID, forKey: .spaceID)
        try c.encodeIfPresent(boxName, forKey: .boxName)
        try c.encodeIfPresent(enabled, forKey: .enabled)
        if let config, !config.isEmpty { try c.encode(config, forKey: .config) }
        if ifVersion != 0 { try c.encode(ifVersion, forKey: .ifVersion) }
    }
}

public struct RelayV2PluginAccount: Codable, Equatable {
    public let bindingID: String
    public let scopeKey: String
    public let username: String
    public let mode: String
    public let metaJSON: String?
    public let updatedAt: Int64?

    enum CodingKeys: String, CodingKey {
        case username, mode
        case bindingID = "binding_id"
        case scopeKey = "scope_key"
        case metaJSON = "meta_json"
        case updatedAt = "updated_at"
    }
}

/// A registered v2 device (never includes the token).
public struct RelayV2Device: Codable, Equatable {
    public let id: String
    public let name: String
    public let publicKey: String
    public let isAdmin: Bool
    public let revoked: Bool
    public let createdAt: Int64

    enum CodingKeys: String, CodingKey {
        case id, name, revoked
        case publicKey = "public_key"
        case isAdmin = "is_admin"
        case createdAt = "created_at"
    }

    public init(id: String, name: String = "", publicKey: String = "", isAdmin: Bool = false, revoked: Bool = false, createdAt: Int64 = 0) {
        self.id = id
        self.name = name
        self.publicKey = publicKey
        self.isAdmin = isAdmin
        self.revoked = revoked
        self.createdAt = createdAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? ""
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        publicKey = try c.decodeIfPresent(String.self, forKey: .publicKey) ?? ""
        isAdmin = try c.decodeIfPresent(Bool.self, forKey: .isAdmin) ?? false
        revoked = try c.decodeIfPresent(Bool.self, forKey: .revoked) ?? false
        createdAt = try c.decodeIfPresent(Int64.self, forKey: .createdAt) ?? 0
    }
}

/// Result of `RelayV2Client.me()`: the token's device, or `rootAdmin` (and a nil
/// `device`) for the Root Admin secret.
public struct RelayV2Me: Codable, Equatable {
    public let device: RelayV2Device?
    public let rootAdmin: Bool

    enum CodingKeys: String, CodingKey {
        case device
        case rootAdmin = "root_admin"
    }

    public init(device: RelayV2Device? = nil, rootAdmin: Bool = false) {
        self.device = device
        self.rootAdmin = rootAdmin
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        device = try c.decodeIfPresent(RelayV2Device.self, forKey: .device)
        rootAdmin = try c.decodeIfPresent(Bool.self, forKey: .rootAdmin) ?? false
    }
}

public final class RelayV2Client {
    public let baseURL: String
    public let accessPassword: String
    public let token: String
    private let session: URLSession

    public init(baseURL: String, accessPassword: String, token: String, allowLocal: Bool = false, session: URLSession = .shared) throws {
        let trimmed = baseURL.trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let u = URL(string: trimmed), let scheme = u.scheme, let host = u.host else {
            throw RelayV2Error.invalidURL
        }
        if scheme == "http" {
            let lh = host.lowercased()
            guard allowLocal && (lh == "127.0.0.1" || lh == "localhost" || lh == "::1") else {
                throw RelayV2Error.insecureTransport
            }
        } else if scheme != "https" {
            throw RelayV2Error.invalidURL
        }
        self.baseURL = trimmed
        self.accessPassword = accessPassword
        self.token = token
        self.session = session
    }

    public var wsURL: URL {
        let s = baseURL.hasPrefix("https://")
            ? "wss://" + baseURL.dropFirst("https://".count) + "/v2/ws"
            : "ws://" + baseURL.dropFirst("http://".count) + "/v2/ws"
        return URL(string: s)!
    }

    /// Lowercase 64-char hex SHA-256 (matches protocol/v2/vectors.json).
    public static func hashSecret(_ plain: String) -> String {
        let digest = SHA256.hash(data: Data(plain.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Encodes a `/v2/ws` binary stream frame: `[16-byte streamID][chunk]`.
    public static func encodeStreamFrame(streamID: String, payload: Data) throws -> Data {
        let sid = Data(streamID.utf8)
        guard sid.count == 16 else { throw RelayV2Error.invalidStreamID }
        var out = Data(capacity: 16 + payload.count)
        out.append(sid)
        out.append(payload)
        return out
    }

    /// Decodes a `/v2/ws` binary stream frame into `(streamID, payload)`.
    public static func decodeStreamFrame(_ frame: Data) throws -> (String, Data) {
        guard frame.count >= 16, let sid = String(data: frame.prefix(16), encoding: .utf8) else {
            throw RelayV2Error.shortBinaryFrame
        }
        return (sid, frame.dropFirst(16))
    }

    /// Deterministic SyncApp 3-tier transfer routing policy (prevents LAN/Pipe/Box races).
    public static func chooseRoute(lanReachable: Bool, peerOnline: Bool) -> RelayV2Route {
        if lanReachable { return .lanDirect }
        if peerOnline { return .pipeStream }
        return .boxEphemeral
    }

    private func makeRequest(method: String, path: String) -> URLRequest {
        var req = URLRequest(url: URL(string: baseURL + path)!)
        req.httpMethod = method
        if !accessPassword.isEmpty { req.setValue(accessPassword, forHTTPHeaderField: "Relay-Access") }
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        return req
    }

    public func putBoxItem(space: String, box: String, data: Data, contentType: String = "application/octet-stream", metaJSON: String? = nil, ttlSec: Int64 = 86400) async throws -> RelayV2BoxItem {
        let suffix = ttlSec > 0 ? "?ttl=\(ttlSec)" : ""
        var req = makeRequest(method: "POST", path: "/v2/spaces/\(space)/boxes/\(box)/items\(suffix)")
        req.setValue(contentType, forHTTPHeaderField: "Content-Type")
        if let metaJSON, !metaJSON.isEmpty { req.setValue(metaJSON, forHTTPHeaderField: "X-Box-Meta") }
        req.httpBody = data
        let (body, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else { throw RelayV2Error.httpStatus(code) }
        struct Envelope: Decodable { let item: RelayV2BoxItem }
        return try JSONDecoder().decode(Envelope.self, from: body).item
    }

    public func listBoxItems(space: String, box: String, afterSeq: Int64 = 0, limit: Int = 100) async throws -> [RelayV2BoxItem] {
        let req = makeRequest(method: "GET", path: "/v2/spaces/\(space)/boxes/\(box)/items?after=\(afterSeq)&limit=\(limit)")
        let (body, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw RelayV2Error.httpStatus(code) }
        struct Envelope: Decodable { let items: [RelayV2BoxItem] }
        return try JSONDecoder().decode(Envelope.self, from: body).items
    }

    public func downloadBoxItem(space: String, box: String, itemID: String) async throws -> Data {
        let req = makeRequest(method: "GET", path: "/v2/spaces/\(space)/boxes/\(box)/items/\(itemID)")
        let (body, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw RelayV2Error.httpStatus(code) }
        return body
    }

    public func ackBoxItem(space: String, box: String, itemID: String) async throws {
        let req = makeRequest(method: "DELETE", path: "/v2/spaces/\(space)/boxes/\(box)/items/\(itemID)")
        let (_, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else { throw RelayV2Error.httpStatus(code) }
    }

    /* ───────── Admin plugin API (/v2/admin/plugins) ───────── */

    private static let pathSegmentAllowed: CharacterSet = {
        var set = CharacterSet.urlPathAllowed
        set.remove(charactersIn: "/")
        return set
    }()

    static func escapePathSegment(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: pathSegmentAllowed) ?? s
    }

    private func pluginPath(_ pluginID: String, _ mount: String) -> String {
        "/v2/admin/plugins/\(Self.escapePathSegment(pluginID))/\(Self.escapePathSegment(mount))"
    }

    private func adminJSON<T: Decodable>(_ method: String, _ path: String, body: Data? = nil, as type: T.Type) async throws -> T {
        var req = makeRequest(method: method, path: path)
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = body
        }
        let (data, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else {
            let text = String(data: data.prefix(4096), encoding: .utf8) ?? ""
            throw RelayV2Error.api(status: code, body: text.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// The device the client's token belongs to. `rootAdmin` is true (and `device`
    /// nil) for the Root Admin secret. Older servers answer a plain-text 404/405:
    /// check `RelayV2Error.isUnsupported`.
    public func me() async throws -> RelayV2Me {
        try await adminJSON("GET", "/v2/me", as: RelayV2Me.self)
    }

    /// Registered plugins with their config schemas.
    public func pluginCatalog() async throws -> [RelayV2PluginInfo] {
        struct Envelope: Decodable { let plugins: [RelayV2PluginInfo]? }
        return try await adminJSON("GET", "/v2/admin/plugins", as: Envelope.self).plugins ?? []
    }

    /// One binding (public view) regardless of its enabled state.
    public func getPlugin(pluginID: String, mount: String) async throws -> RelayV2PluginBinding {
        struct Envelope: Decodable { let binding: RelayV2PluginBinding }
        return try await adminJSON("GET", pluginPath(pluginID, mount), as: Envelope.self).binding
    }

    /// Merges a partial update into an existing binding (never creates one).
    /// Older servers answer a plain-text 404/405: check `RelayV2Error.isUnsupported`.
    public func patchPlugin(pluginID: String, mount: String, patch: RelayV2PluginPatch) async throws -> RelayV2PluginBinding {
        struct Envelope: Decodable { let binding: RelayV2PluginBinding }
        let body = try JSONEncoder().encode(patch)
        return try await adminJSON("PATCH", pluginPath(pluginID, mount), body: body, as: Envelope.self).binding
    }

    /// Stores an account whose plaintext password the server hashes with salted scrypt.
    public func upsertPluginAccountPassword(pluginID: String, mount: String, scopeKey: String, username: String, password: String, mode: String) async throws -> RelayV2PluginAccount {
        struct Envelope: Decodable { let account: RelayV2PluginAccount }
        let body = try JSONEncoder().encode(["scope_key": scopeKey, "username": username, "password": password, "mode": mode])
        return try await adminJSON("PUT", pluginPath(pluginID, mount) + "/accounts", body: body, as: Envelope.self).account
    }
}

/// Sealed bridge payloads ("crs1"): bridge plugins (Webhook, Drop, WebDAV queue) seal plaintext
/// to a recipient X25519 key before it touches relay disk. Wire format (see sdk/go/v2client/sealed.go):
/// `"CRS1" || crypto_box_seal(32-byte key) (80) || nonce prefix (16) || frames`, each frame
/// `u32 BE length || secretbox(chunk, prefix || u64 BE counter)`; the final frame sets the counter's high bit.
public enum RelayV2Sealed {
    public static let scheme = "crs1"
    /// Content type of sealed queue items; the original type is in item meta "content_type".
    public static let contentType = "application/vnd.common-relay.sealed"
    static let magic: [UInt8] = Array("CRS1".utf8)
    static let chunkSize = 64 << 10
    static let sealedKeyLength = 32 + 48
    static let headerLength = 4 + sealedKeyLength + 16
    static let macLength = 16
    static let finalFrameBit: UInt64 = 1 << 63

    /// Decodes a 64-char hex X25519 key (public or private).
    public static func parseKey(_ hex: String) throws -> Data {
        guard let key = try? Data(relayHex: hex.trimmingCharacters(in: .whitespacesAndNewlines)), key.count == 32 else {
            throw RelayV2Error.invalidKey
        }
        return key
    }

    /// Fresh X25519 key pair for a binding's seal_public_key.
    public static func generateKeyPair() throws -> (publicHex: String, privateHex: String) {
        guard sodium_init() >= 0 else { throw RelayV2Error.invalidKey }
        var pk = [UInt8](repeating: 0, count: 32), sk = [UInt8](repeating: 0, count: 32)
        guard crypto_box_keypair(&pk, &sk) == 0 else { throw RelayV2Error.invalidKey }
        defer { sodium_memzero(&sk, sk.count) }
        return (Data(pk).relayHex, Data(sk).relayHex)
    }

    /// True when data starts with the sealed-payload magic.
    public static func isSealed(_ head: Data) -> Bool {
        head.count >= 4 && Array(head.prefix(4)) == magic
    }

    /// Decrypts a complete sealed payload with the recipient key pair.
    public static func open(_ sealed: Data, publicKey: Data, secretKey: Data) throws -> Data {
        guard publicKey.count == 32, secretKey.count == 32 else { throw RelayV2Error.invalidKey }
        guard sodium_init() >= 0 else { throw RelayV2Error.sealedCorrupt }
        let bytes = [UInt8](sealed)
        guard bytes.count >= headerLength, isSealed(sealed) else { throw RelayV2Error.sealedCorrupt }
        let pk = [UInt8](publicKey)
        var sk = [UInt8](secretKey)
        defer { sodium_memzero(&sk, sk.count) }
        let sealedKey = Array(bytes[4..<(4 + sealedKeyLength)])
        var key = [UInt8](repeating: 0, count: 32)
        defer { sodium_memzero(&key, key.count) }
        guard crypto_box_seal_open(&key, sealedKey, UInt64(sealedKey.count), pk, sk) == 0 else {
            throw RelayV2Error.sealedCorrupt
        }
        let prefix = Array(bytes[(4 + sealedKeyLength)..<headerLength])
        var pos = headerLength
        var out = Data()
        var ctr: UInt64 = 0
        while true {
            guard bytes.count - pos >= 4 else { throw RelayV2Error.sealedCorrupt }
            let len = Int(bytes[pos]) << 24 | Int(bytes[pos + 1]) << 16 | Int(bytes[pos + 2]) << 8 | Int(bytes[pos + 3])
            pos += 4
            guard len >= macLength, len <= chunkSize + macLength, len <= bytes.count - pos else {
                throw RelayV2Error.sealedCorrupt
            }
            let frame = Array(bytes[pos..<(pos + len)])
            pos += len
            let last = pos == bytes.count
            let c = last ? ctr | finalFrameBit : ctr
            var nonce = prefix
            for shift in stride(from: 56, through: 0, by: -8) { nonce.append(UInt8(truncatingIfNeeded: c >> UInt64(shift))) }
            var plain = [UInt8](repeating: 0, count: max(1, len - macLength))
            guard crypto_secretbox_open_easy(&plain, frame, UInt64(len), nonce, key) == 0 else {
                throw RelayV2Error.sealedCorrupt
            }
            out.append(contentsOf: plain.prefix(len - macLength))
            if last { return out }
            ctr += 1
        }
    }
}
