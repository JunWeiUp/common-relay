import XCTest
@testable import CommonRelay

final class V2ClientTests: XCTestCase {
    func testProtocolV2VectorsAndRouting() throws {
        let v = try ProtocolVectors.load("vectors.json")
        let hashes = v["hash_secret"] as! [[String: Any]]
        XCTAssertFalse(hashes.isEmpty)
        for item in hashes {
            XCTAssertEqual(RelayV2Client.hashSecret(item["input"] as! String), item["sha256"] as? String, item["use"] as? String ?? "")
        }
        let vector = v["binary_stream_frame"] as! [String: Any]
        let streamID = vector["stream_id"] as! String
        let payload = Data((vector["payload_utf8"] as! String).utf8)
        let frame = try RelayV2Client.encodeStreamFrame(streamID: streamID, payload: payload)
        XCTAssertEqual(frame.relayHex, vector["frame_hex"] as? String)
        let (sid, decoded) = try RelayV2Client.decodeStreamFrame(try Data(relayHex: vector["frame_hex"] as! String))
        XCTAssertEqual(sid, streamID)
        XCTAssertEqual(decoded, payload)

        XCTAssertEqual(RelayV2Client.chooseRoute(lanReachable: true, peerOnline: true), .lanDirect)
        XCTAssertEqual(RelayV2Client.chooseRoute(lanReachable: false, peerOnline: true), .pipeStream)
        XCTAssertEqual(RelayV2Client.chooseRoute(lanReachable: false, peerOnline: false), .boxEphemeral)

        let c = try RelayV2Client(baseURL: "https://relay.example/", accessPassword: "acc", token: "tok")
        XCTAssertEqual(c.wsURL.absoluteString, "wss://relay.example/v2/ws")
        XCTAssertThrowsError(try RelayV2Client(baseURL: "http://relay.example", accessPassword: "acc", token: "tok"))
    }

    // MARK: - Admin plugin API

    private func stubbedClient() throws -> RelayV2Client {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [V2StubProtocol.self]
        return try RelayV2Client(baseURL: "https://relay.example", accessPassword: "acc", token: "tok", session: URLSession(configuration: cfg))
    }

    override func tearDown() {
        V2StubProtocol.reset()
        super.tearDown()
    }

    func testPatchPluginRequestShape() async throws {
        V2StubProtocol.respond(200, #"{"ok":true,"binding":{"id":"b1","plugin_id":"webhook","mount":"gh hooks","space_id":"personal","box_name":"inbox","config_json":"{\"tag\":\"x\"}","enabled":false,"updated_at":7,"config_version":4,"secret_keys":["hmac_secret"],"sealed":true,"summary":{"tag":"x","has_hmac":true}}}"#)
        let c = try stubbedClient()
        let b = try await c.patchPlugin(pluginID: "webhook", mount: "gh hooks", patch: RelayV2PluginPatch(enabled: false, config: ["tag": .string("x"), "hmac_secret": .null]))
        let req = try XCTUnwrap(V2StubProtocol.lastRequest)
        XCTAssertEqual(req.httpMethod, "PATCH")
        XCTAssertEqual(req.url?.absoluteString, "https://relay.example/v2/admin/plugins/webhook/gh%20hooks")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer tok")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Relay-Access"), "acc")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Content-Type"), "application/json")
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: V2StubProtocol.lastBody) as? [String: Any])
        XCTAssertEqual(Set(body.keys), ["enabled", "config"])
        XCTAssertEqual(body["enabled"] as? Bool, false)
        let config = try XCTUnwrap(body["config"] as? [String: Any])
        XCTAssertEqual(config["tag"] as? String, "x")
        XCTAssertTrue(config["hmac_secret"] is NSNull)
        XCTAssertEqual(b.configVersion, 4)
        XCTAssertEqual(b.secretKeys, ["hmac_secret"])
        XCTAssertTrue(b.sealed)
        XCTAssertEqual(b.summary?.hasHMAC, true)

        V2StubProtocol.respond(200, #"{"ok":true,"binding":{"id":"b1","plugin_id":"drop","mount":"m"}}"#)
        let old = try await c.patchPlugin(pluginID: "a/b", mount: "m", patch: RelayV2PluginPatch(spaceID: "s", boxName: "q", ifVersion: 9))
        XCTAssertEqual(V2StubProtocol.lastRequest?.url?.absoluteString, "https://relay.example/v2/admin/plugins/a%2Fb/m")
        let body2 = try XCTUnwrap(JSONSerialization.jsonObject(with: V2StubProtocol.lastBody) as? [String: Any])
        XCTAssertEqual(body2["space_id"] as? String, "s")
        XCTAssertEqual(body2["box_name"] as? String, "q")
        XCTAssertEqual(body2["if_version"] as? Int, 9)
        XCTAssertNil(body2["config"])
        XCTAssertEqual(old.configVersion, 0)
        XCTAssertEqual(old.secretKeys, [])
        XCTAssertFalse(old.sealed)
    }

    func testCatalogGetAndAccountPassword() async throws {
        let c = try stubbedClient()
        V2StubProtocol.respond(200, #"{"ok":true,"registered":["drop"],"plugins":[{"id":"drop","required_trust":"bridge_allowed","schema":[{"key":"token","type":"string","secret":true}]}],"bindings":[]}"#)
        let cat = try await c.pluginCatalog()
        XCTAssertEqual(V2StubProtocol.lastRequest?.httpMethod, "GET")
        XCTAssertEqual(V2StubProtocol.lastRequest?.url?.path, "/v2/admin/plugins")
        XCTAssertEqual(cat.first?.requiredTrust, "bridge_allowed")
        XCTAssertEqual(cat.first?.schema?.first?.secret, true)

        V2StubProtocol.respond(200, #"{"ok":true,"binding":{"id":"b2","plugin_id":"drop","mount":"m","enabled":true}}"#)
        let b = try await c.getPlugin(pluginID: "drop", mount: "m")
        XCTAssertEqual(V2StubProtocol.lastRequest?.httpMethod, "GET")
        XCTAssertEqual(V2StubProtocol.lastRequest?.url?.path, "/v2/admin/plugins/drop/m")
        XCTAssertEqual(b.id, "b2")

        V2StubProtocol.respond(200, #"{"ok":true,"account":{"binding_id":"b2","scope_key":"","username":"u","mode":"rw","meta_json":"{}","updated_at":1}}"#)
        let a = try await c.upsertPluginAccountPassword(pluginID: "webdav", mount: "m", scopeKey: "", username: "u", password: "pw", mode: "rw")
        XCTAssertEqual(V2StubProtocol.lastRequest?.httpMethod, "PUT")
        XCTAssertEqual(V2StubProtocol.lastRequest?.url?.path, "/v2/admin/plugins/webdav/m/accounts")
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: V2StubProtocol.lastBody) as? [String: String])
        XCTAssertEqual(body, ["scope_key": "", "username": "u", "password": "pw", "mode": "rw"])
        XCTAssertEqual(a.username, "u")
    }

    func testUnsupportedDetection() async throws {
        let c = try stubbedClient()
        V2StubProtocol.respond(404, "404 page not found\n")
        do {
            _ = try await c.patchPlugin(pluginID: "drop", mount: "m", patch: RelayV2PluginPatch(enabled: true))
            XCTFail("expected error")
        } catch let e as RelayV2Error {
            XCTAssertEqual(e, .api(status: 404, body: "404 page not found"))
            XCTAssertTrue(e.isUnsupported)
        }
        V2StubProtocol.respond(404, #"{"ok":false,"error":"not found"}"#)
        do {
            _ = try await c.getPlugin(pluginID: "drop", mount: "missing")
            XCTFail("expected error")
        } catch let e as RelayV2Error {
            XCTAssertFalse(e.isUnsupported)
        }
        XCTAssertTrue(RelayV2Error.isUnsupported(status: 405, body: "{}"))
        XCTAssertTrue(RelayV2Error.isUnsupported(status: 501, body: ""))
        XCTAssertTrue(RelayV2Error.isUnsupported(status: 404, body: ""))
        XCTAssertFalse(RelayV2Error.isUnsupported(status: 409, body: "conflict"))
        XCTAssertFalse(RelayV2Error.isUnsupported(status: 404, body: "  {\"ok\":false}"))
    }

    func testMe() async throws {
        let c = try stubbedClient()
        V2StubProtocol.respond(200, #"{"ok":true,"device":{"id":"d1","name":"phone","public_key":"pk","is_admin":true,"revoked":false,"created_at":5}}"#)
        let me = try await c.me()
        let req = try XCTUnwrap(V2StubProtocol.lastRequest)
        XCTAssertEqual(req.httpMethod, "GET")
        XCTAssertEqual(req.url?.absoluteString, "https://relay.example/v2/me")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer tok")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Relay-Access"), "acc")
        XCTAssertFalse(me.rootAdmin)
        XCTAssertEqual(me.device, RelayV2Device(id: "d1", name: "phone", publicKey: "pk", isAdmin: true, revoked: false, createdAt: 5))

        V2StubProtocol.respond(200, #"{"ok":true,"root_admin":true}"#)
        let root = try await c.me()
        XCTAssertTrue(root.rootAdmin)
        XCTAssertNil(root.device)

        V2StubProtocol.respond(404, "404 page not found\n")
        do {
            _ = try await c.me()
            XCTFail("expected error")
        } catch let e as RelayV2Error {
            XCTAssertTrue(e.isUnsupported)
        }
    }

    // MARK: - Sealed (crs1)

    func testOpenSealedGoVectors() throws {
        let v = try ProtocolVectors.load("sealed-vectors.json")
        XCTAssertEqual(RelayV2Sealed.contentType, v["content_type"] as? String)
        let pk = try RelayV2Sealed.parseKey(v["recipient_public"] as! String)
        let sk = try RelayV2Sealed.parseKey(v["recipient_private"] as! String)
        var sealed: [String: Data] = [:]
        let valid = v["valid"] as! [[String: Any]]
        XCTAssertEqual(Set(valid.map { $0["name"] as! String }), ["hello", "empty", "two_frames"])
        for item in valid {
            let name = item["name"] as! String
            let bytes = try XCTUnwrap(Data(base64Encoded: item["sealed_b64"] as! String), name)
            sealed[name] = bytes
            XCTAssertTrue(RelayV2Sealed.isSealed(bytes), name)
            let plain = try RelayV2Sealed.open(bytes, publicKey: pk, secretKey: sk)
            XCTAssertEqual(plain.count, item["plaintext_length"] as? Int, name)
            XCTAssertEqual(RelayGroups.digest(plain), item["plaintext_sha256"] as? String, name)
            if let hex = item["plaintext_hex"] as? String { XCTAssertEqual(plain, try Data(relayHex: hex), name) }
            if name == "two_frames" { XCTAssertEqual(plain, Data((0..<plain.count).map { UInt8(($0 * 7 + 3) & 0xff) })) }
        }
        XCTAssertFalse(RelayV2Sealed.isSealed(Data("CRS".utf8)))
        XCTAssertFalse(RelayV2Sealed.isSealed(Data("hello".utf8)))

        let invalid = v["invalid"] as! [[String: Any]]
        XCTAssertFalse(invalid.isEmpty)
        for item in invalid {
            let name = item["name"] as! String
            var bytes = try XCTUnwrap(sealed[item["base"] as! String], name)
            switch item["op"] as! String {
            case "truncate": bytes = bytes.prefix(item["length"] as! Int)
            case "append": bytes += try Data(relayHex: item["hex"] as! String)
            case "flip": let i = bytes.startIndex + (item["offset"] as! Int); bytes[i] ^= 0x01
            default: XCTFail("unknown op \(name)"); continue
            }
            XCTAssertThrowsError(try RelayV2Sealed.open(Data(bytes), publicKey: pk, secretKey: sk), name)
        }
        let wrongPK = try RelayV2Sealed.parseKey(v["wrong_public"] as! String)
        let wrongSK = try RelayV2Sealed.parseKey(v["wrong_private"] as! String)
        XCTAssertThrowsError(try RelayV2Sealed.open(sealed["hello"]!, publicKey: wrongPK, secretKey: wrongSK)) { error in
            XCTAssertEqual(error as? RelayV2Error, .sealedCorrupt)
        }
        XCTAssertThrowsError(try RelayV2Sealed.parseKey("abcd"))
    }

    func testGeneratedKeyPairIsConsistent() throws {
        let kp = try RelayV2Sealed.generateKeyPair()
        XCTAssertEqual(kp.publicHex.count, 64)
        XCTAssertEqual(kp.privateHex.count, 64)
        let sk = try RelayV2Sealed.parseKey(kp.privateHex)
        let identity = try RelayIdentity(app: "a", group: "g", device: "d", secretKey: sk, trustedPeers: [:])
        XCTAssertEqual(identity.publicKey.relayHex, kp.publicHex)
        XCTAssertNotEqual(try RelayV2Sealed.generateKeyPair().publicHex, kp.publicHex)
    }
}

final class V2StubProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var status = 200
    private static var responseBody = Data()
    private(set) static var lastRequest: URLRequest?
    private(set) static var lastBody = Data()

    static func respond(_ code: Int, _ body: String) {
        lock.lock(); defer { lock.unlock() }
        status = code; responseBody = Data(body.utf8)
    }

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        status = 200; responseBody = Data(); lastRequest = nil; lastBody = Data()
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        var body = request.httpBody ?? Data()
        if body.isEmpty, let stream = request.httpBodyStream {
            stream.open()
            var buf = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let n = stream.read(&buf, maxLength: buf.count)
                if n <= 0 { break }
                body.append(buf, count: n)
            }
            stream.close()
        }
        Self.lock.lock()
        Self.lastRequest = request
        Self.lastBody = body
        let code = Self.status, data = Self.responseBody
        Self.lock.unlock()
        let resp = HTTPURLResponse(url: request.url!, statusCode: code, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
