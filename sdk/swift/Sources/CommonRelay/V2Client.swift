import Foundation
import CryptoKit

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
}
