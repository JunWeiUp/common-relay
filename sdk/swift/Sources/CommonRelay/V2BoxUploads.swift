import Foundation
import CryptoKit

public struct RelayV2BoxUpload: Codable, Equatable, Sendable {
    public let id: String
    public let spaceID: String
    public let boxName: String
    public let key: String?
    public let sender: String?
    public let totalSize: Int64
    public let offset: Int64
    public let contentType: String
    public let metaJSON: String
    public let expiresAt: Int64
    public let createdAt: Int64

    enum CodingKeys: String, CodingKey {
        case id, key, sender, offset
        case spaceID = "space_id"
        case boxName = "box_name"
        case totalSize = "total_size"
        case contentType = "content_type"
        case metaJSON = "meta_json"
        case expiresAt = "expires_at"
        case createdAt = "created_at"
    }
}

extension RelayV2Client {
    private func boxUploadsURL(spaceID: String, boxName: String, suffix: String = "") throws -> URL {
        let sp = spaceID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? spaceID
        let segs = boxName.split(separator: "/").map {
            String($0).addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? String($0)
        }.joined(separator: "/")
        let raw = "\(baseURL)/v2/spaces/\(sp)/boxes/\(segs)/uploads\(suffix)"
        guard let url = URL(string: raw) else { throw RelayV2Error.invalidURL }
        return url
    }

    private func authorizedRequest(url: URL, method: String, contentType: String? = nil) -> URLRequest {
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        if !accessPassword.isEmpty {
            req.setValue(accessPassword, forHTTPHeaderField: "Relay-Access")
        }
        if let contentType {
            req.setValue(contentType, forHTTPHeaderField: "Content-Type")
        }
        return req
    }

    public func createBoxUpload(
        spaceID: String,
        boxName: String,
        totalSize: Int64,
        key: String = "",
        contentType: String = "application/octet-stream",
        metaJSON: String = "{}",
        ttlSeconds: Int64 = 0
    ) async throws -> RelayV2BoxUpload {
        let url = try boxUploadsURL(spaceID: spaceID, boxName: boxName)
        var req = authorizedRequest(url: url, method: "POST", contentType: "application/json")
        var body: [String: Any] = [
            "total_size": totalSize,
            "content_type": contentType,
            "meta": metaJSON,
        ]
        if !key.isEmpty { body["key"] = key }
        if ttlSeconds > 0 { body["ttl"] = ttlSeconds }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            throw RelayV2Error.api(status: code, body: String(data: data, encoding: .utf8) ?? "")
        }
        struct Wrap: Decodable { let upload: RelayV2BoxUpload }
        return try JSONDecoder().decode(Wrap.self, from: data).upload
    }

    public func getBoxUpload(spaceID: String, boxName: String, uploadID: String) async throws -> RelayV2BoxUpload {
        let uid = uploadID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? uploadID
        let url = try boxUploadsURL(spaceID: spaceID, boxName: boxName, suffix: "/\(uid)")
        let req = authorizedRequest(url: url, method: "GET")
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            throw RelayV2Error.api(status: code, body: String(data: data, encoding: .utf8) ?? "")
        }
        struct Wrap: Decodable { let upload: RelayV2BoxUpload }
        return try JSONDecoder().decode(Wrap.self, from: data).upload
    }

    public func appendBoxUploadChunk(
        spaceID: String,
        boxName: String,
        uploadID: String,
        offset: Int64,
        chunk: Data
    ) async throws -> RelayV2BoxUpload {
        let uid = uploadID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? uploadID
        let url = try boxUploadsURL(spaceID: spaceID, boxName: boxName, suffix: "/\(uid)?offset=\(offset)")
        var req = authorizedRequest(url: url, method: "PATCH", contentType: "application/octet-stream")
        req.httpBody = chunk
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            throw RelayV2Error.api(status: code, body: String(data: data, encoding: .utf8) ?? "")
        }
        struct Wrap: Decodable { let upload: RelayV2BoxUpload }
        return try JSONDecoder().decode(Wrap.self, from: data).upload
    }

    public func completeBoxUpload(
        spaceID: String,
        boxName: String,
        uploadID: String,
        sha256Hex: String = "",
        expectedETag: String = ""
    ) async throws -> Data {
        let uid = uploadID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? uploadID
        let url = try boxUploadsURL(spaceID: spaceID, boxName: boxName, suffix: "/\(uid)/complete")
        var req = authorizedRequest(url: url, method: "POST", contentType: "application/json")
        var body: [String: String] = [:]
        if !sha256Hex.isEmpty { body["sha256"] = sha256Hex }
        if !expectedETag.isEmpty { body["expected_etag"] = expectedETag }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            throw RelayV2Error.api(status: code, body: String(data: data, encoding: .utf8) ?? "")
        }
        return data
    }

    public func abortBoxUpload(spaceID: String, boxName: String, uploadID: String) async throws {
        let uid = uploadID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? uploadID
        let url = try boxUploadsURL(spaceID: spaceID, boxName: boxName, suffix: "/\(uid)")
        let req = authorizedRequest(url: url, method: "DELETE")
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            throw RelayV2Error.api(status: code, body: String(data: data, encoding: .utf8) ?? "")
        }
    }

    public func uploadBoxResumable(
        spaceID: String,
        boxName: String,
        data: Data,
        key: String = "",
        contentType: String = "application/octet-stream",
        metaJSON: String = "{}",
        chunkSize: Int = 256 * 1024,
        ttlSeconds: Int64 = 0,
        expectedETag: String = ""
    ) async throws -> Data {
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        var up = try await createBoxUpload(
            spaceID: spaceID,
            boxName: boxName,
            totalSize: Int64(data.count),
            key: key,
            contentType: contentType,
            metaJSON: metaJSON,
            ttlSeconds: ttlSeconds
        )
        var offset = 0
        while offset < data.count {
            let end = min(offset + chunkSize, data.count)
            up = try await appendBoxUploadChunk(
                spaceID: spaceID,
                boxName: boxName,
                uploadID: up.id,
                offset: Int64(offset),
                chunk: data.subdata(in: offset..<end)
            )
            offset = Int(up.offset)
        }
        return try await completeBoxUpload(
            spaceID: spaceID,
            boxName: boxName,
            uploadID: up.id,
            sha256Hex: digest,
            expectedETag: expectedETag
        )
    }
}
