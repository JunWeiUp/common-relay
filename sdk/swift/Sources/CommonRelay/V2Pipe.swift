import Foundation

/// Bidirectional E2E-encrypted stream running over Common Relay v2 `/v2/ws` binary frames
/// (`[16-byte streamID][XChaCha20-Poly1305 secretstream chunk]`).
public actor RelayV2Stream {
    public let id: String
    public let peer: String
    private let identity: RelayIdentity
    private let sendFrame: @Sendable (Data) async throws -> Void
    private let sendCloseEvent: @Sendable () async -> Void
    private let sendCreditEvent: (@Sendable (Int) async -> Void)?
    private let tx: SecretStream
    private var rx: SecretStream?
    private var sendSeq: UInt64 = 0
    private var recvSeq: UInt64 = 0
    private var uncreditedRecv = 0
    private var paused = false
    private var pendingCipher: [Data] = []
    private var incoming: [Data] = []
    private var waiters: [CheckedContinuation<Data, Error>] = []
    private var closed = false
    private var closeEventSent = false
    private static let creditBatch = 16

    init(
        id: String,
        peer: String,
        identity: RelayIdentity,
        tx: SecretStream,
        rx: SecretStream?,
        sendFrame: @escaping @Sendable (Data) async throws -> Void,
        sendCloseEvent: @escaping @Sendable () async -> Void,
        sendCreditEvent: (@Sendable (Int) async -> Void)? = nil
    ) {
        self.id = id
        self.peer = peer
        self.identity = identity
        self.tx = tx
        self.rx = rx
        self.sendFrame = sendFrame
        self.sendCloseEvent = sendCloseEvent
        self.sendCreditEvent = sendCreditEvent
    }

    func attachReceiver(_ rx: SecretStream) {
        self.rx = rx
        guard !closed, !pendingCipher.isEmpty else { return }
        let buffered = pendingCipher
        pendingCipher.removeAll()
        for cipher in buffered {
            guard !closed else { break }
            deliver(cipher: cipher)
        }
    }

    func handleCredit(_ seq: Int64) {
        paused = (seq == 0)
    }

    public func send(_ data: Data) async throws {
        guard !closed else { throw RelayError.closed }
        var offset = 0
        while offset < data.count {
            if paused {
                try? await Task.sleep(nanoseconds: 50_000_000)
                paused = false
            }
            guard !closed else { throw RelayError.closed }
            let end = min(offset + 65519, data.count)
            let chunk = data.subdata(in: offset..<end)
            let aad = try identity.aad(from: identity.device, to: peer, kind: "stream", id: id, sequence: sendSeq)
            sendSeq += 1
            let cipher = try tx.push(chunk, aad: aad, final: false)
            let frame = try RelayV2Client.encodeStreamFrame(streamID: id, payload: cipher)
            try await sendFrame(frame)
            offset = end
        }
    }

    public func receive() async throws -> Data {
        if !incoming.isEmpty {
            return incoming.removeFirst()
        }
        if closed {
            return Data()
        }
        return try await withCheckedThrowingContinuation { cont in
            waiters.append(cont)
        }
    }

    func deliver(cipher: Data) {
        guard !closed else { return }
        guard let rx else {
            pendingCipher.append(cipher)
            return
        }
        do {
            let aad = try identity.aad(from: peer, to: identity.device, kind: "stream", id: id, sequence: recvSeq)
            recvSeq += 1
            let plain = try rx.pull(cipher, aad: aad)
            uncreditedRecv += 1
            if uncreditedRecv >= Self.creditBatch {
                uncreditedRecv = 0
                if let sendCreditEvent {
                    Task { await sendCreditEvent(Self.creditBatch) }
                }
            }
            if rx.finished {
                if !plain.isEmpty { enqueue(plain) }
                finishLocal()
            } else {
                enqueue(plain)
            }
        } catch {
            finishLocal(error: error)
            notifyPeerClosed()
        }
    }

    private func notifyPeerClosed() {
        guard !closeEventSent else { return }
        closeEventSent = true
        let sendClose = sendCloseEvent
        Task { await sendClose() }
    }

    func remoteClosed() {
        closeEventSent = true
        finishLocal()
    }

    public func close() async {
        if !closed {
            if !tx.finished {
                if let aad = try? identity.aad(from: identity.device, to: peer, kind: "stream", id: id, sequence: sendSeq),
                   let cipher = try? tx.push(Data(), aad: aad, final: true),
                   let frame = try? RelayV2Client.encodeStreamFrame(streamID: id, payload: cipher) {
                    sendSeq += 1
                    try? await sendFrame(frame)
                }
            }
            finishLocal()
        }
        if !closeEventSent {
            closeEventSent = true
            await sendCloseEvent()
        }
    }

    private func enqueue(_ data: Data) {
        if !waiters.isEmpty {
            let w = waiters.removeFirst()
            w.resume(returning: data)
        } else {
            incoming.append(data)
        }
    }

    private func finishLocal(error: Error? = nil) {
        guard !closed else { return }
        closed = true
        pendingCipher.removeAll()
        let pending = waiters
        waiters.removeAll()
        for w in pending {
            if let error {
                w.resume(throwing: error)
            } else {
                w.resume(returning: Data())
            }
        }
    }
}

/// Leak-free Common Relay v2 Pipe over `NWConnection` + `NWProtocolWebSocket` (`RelaySocket`).
/// Provides E2E-encrypted online messages, presence queries, and zero-disk binary streams
/// on `strict_e2e` Spaces.
public actor RelayV2Pipe {
    public let client: RelayV2Client
    public let space: String
    public let identity: RelayIdentity

    private var socket: RelaySocket?
    private var readerTask: Task<Void, Never>?
    private var streams: [String: RelayV2Stream] = [:]
    private var pendingAccept: [String: CheckedContinuation<RelayV2PipeEvent, Error>] = [:]
    private var pendingPresence: [String: CheckedContinuation<[String], Error>] = [:]
    private var closed = false

    public init(client: RelayV2Client, space: String, identity: RelayIdentity) {
        self.client = client
        self.space = space
        self.identity = identity
    }

    public func connect() async throws -> AsyncThrowingStream<RelayV2PipeEvent, Error> {
        var req = URLRequest(url: client.wsURL)
        if !client.accessPassword.isEmpty {
            req.setValue(client.accessPassword, forHTTPHeaderField: RelayAccess.header)
        }
        req.setValue("Bearer \(client.token)", forHTTPHeaderField: "Authorization")

        let sock = try RelaySocket(request: req, maximumMessageSize: 512 * 1024)
        do {
            try await sock.open()
        } catch {
            sock.cancel()
            throw await RelaySocket.upgradeFailure(error, request: req)
        }
        self.socket = sock
        self.closed = false

        return AsyncThrowingStream { continuation in
            let task = Task { [weak self] in
                guard let self else {
                    continuation.finish()
                    return
                }
                do {
                    while !Task.isCancelled {
                        let msg = try await sock.receive()
                        switch msg {
                        case .data(let frame):
                            await self.handleBinary(frame)
                        case .string(let text):
                            if let ev = try? JSONDecoder().decode(RelayV2PipeEvent.self, from: Data(text.utf8)) {
                                let forward = await self.handleEvent(ev)
                                if forward {
                                    continuation.yield(ev)
                                }
                            }
                        }
                    }
                    continuation.finish()
                } catch {
                    await self.cleanupOnDisconnect(error: error)
                    continuation.finish(throwing: error)
                }
            }
            self.setReaderTask(task)
        }
    }

    private func setReaderTask(_ task: Task<Void, Never>) {
        readerTask = task
    }

    public func peers(timeoutSeconds: Double = 5) async throws -> [String] {
        let reqID = String(RelayIdentity.generateSecretKey().prefix(8).relayHex)
        try await sendJSON([
            "type": "presence",
            "space": space,
            "id": reqID,
        ])
        return try await withCheckedThrowingContinuation { cont in
            pendingPresence[reqID] = cont
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
                await self?.timeoutPresence(reqID)
            }
        }
    }

    private func timeoutPresence(_ reqID: String) {
        if let c = pendingPresence.removeValue(forKey: reqID) {
            c.resume(throwing: RelayError.closed)
        }
    }

    @discardableResult
    public func sendMessage(
        to peer: String,
        topic: String,
        plaintext: Data,
        offline: Bool = false,
        ttlSeconds: Int? = nil,
        id: String? = nil,
        kind: String = "message"
    ) async throws -> String {
        let msgID = id ?? String(RelayIdentity.generateSecretKey().prefix(12).relayHex)
        let sealed = try identity.seal(to: peer, kind: kind, id: msgID, value: [
            "data": plaintext.base64EncodedString(),
        ])
        var payload: [String: Any] = [
            "type": "msg",
            "space": space,
            "id": msgID,
            "to": peer,
            "topic": topic,
            "body": sealed,
        ]
        if offline {
            payload["offline"] = true
        }
        if let ttl = ttlSeconds, ttl > 0 {
            payload["ttl"] = ttl
        }
        try await sendJSON(payload)
        return msgID
    }

    /// Sends a `/v2/ws` `ack` for an offline message (or to drop an undecryptable
    /// message per §4.5 after durable local processing / roster verification).
    public func ackMessage(from sender: String, id: String, space overrideSpace: String? = nil) async throws {
        try await sendJSON([
            "type": "ack",
            "space": overrideSpace ?? space,
            "from": sender,
            "id": id,
        ])
    }

    /// Requests the next batch (up to 256) of un-ACKed offline messages for this
    /// Space without reconnecting. Ends with a `msg.pull.done` event.
    @discardableResult
    public func pullOfflineMessages(id: String? = nil) async throws -> String {
        let reqID = id ?? String(RelayIdentity.generateSecretKey().prefix(8).relayHex)
        try await sendJSON([
            "type": "msg.pull",
            "space": space,
            "id": reqID,
        ])
        return reqID
    }

    /// Grants flow-control credit (`seq` frames, or `0` to request pause) for a ready stream.
    public func sendStreamCredit(streamID: String, credit: Int) async throws {
        guard credit >= 0 else {
            throw RelayError.invalid("stream credit must be >= 0")
        }
        try await sendJSON([
            "type": "stream.credit",
            "space": space,
            "id": streamID,
            "seq": credit,
        ])
    }

    public nonisolated func isTrustedSender(_ deviceID: String) -> Bool {
        identity.isTrusted(deviceID)
    }

    public nonisolated func openMessage(_ event: RelayV2PipeEvent) throws -> Data {
        guard let from = event.from, let id = event.id, let body = event.body else {
            throw RelayError.invalid("missing message fields")
        }
        let opened: [String: Any]
        if let v = try? identity.open(from: from, kind: "message", id: id, body: body) {
            opened = v
        } else {
            opened = try identity.open(from: from, kind: "msg", id: id, body: body)
        }
        guard let b64 = opened["data"] as? String, let data = Data(base64Encoded: b64) else {
            throw RelayError.invalid("invalid message data")
        }
        return data
    }

    /// Attempts to decrypt a `msg` event without throwing on §4.5 undecryptable
    /// envelopes. Returns `nil` if the sender is untrusted or authentication fails.
    public nonisolated func tryOpenMessage(_ event: RelayV2PipeEvent) -> Data? {
        try? openMessage(event)
    }

    public func openStream(to peer: String, topic: String = "stream", timeoutSeconds: Double = 15) async throws -> RelayV2Stream {
        let sid = String(RelayIdentity.generateSecretKey().prefix(8).relayHex)
        let tx = try SecretStream()
        let sealed = try identity.seal(to: peer, kind: "stream.open", id: sid, value: tx.descriptor)
        let stream = RelayV2Stream(
            id: sid,
            peer: peer,
            identity: identity,
            tx: tx,
            rx: nil,
            sendFrame: { [weak self] frame in
                guard let self else { throw RelayError.closed }
                try await self.sendBinary(frame)
            },
            sendCloseEvent: { [weak self] in
                await self?.closeStream(id: sid)
            },
            sendCreditEvent: { [weak self] n in
                try? await self?.sendStreamCredit(streamID: sid, credit: n)
            }
        )
        streams[sid] = stream
        do {
            try await sendJSON([
                "type": "stream.open",
                "space": space,
                "id": sid,
                "to": peer,
                "topic": topic,
                "body": sealed,
            ])
            let acc: RelayV2PipeEvent = try await withCheckedThrowingContinuation { cont in
                pendingAccept[sid] = cont
                Task { [weak self] in
                    try? await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
                    await self?.timeoutAccept(sid)
                }
            }
            guard let body = acc.body else { throw RelayError.invalid("missing stream.accept body") }
            let desc = try identity.open(from: peer, kind: "stream.accept", id: sid, body: body)
            let rx = try SecretStream(descriptor: desc)
            await stream.attachReceiver(rx)
            return stream
        } catch {
            streams.removeValue(forKey: sid)
            await stream.remoteClosed()
            throw error
        }
    }

    private func timeoutAccept(_ sid: String) {
        if let c = pendingAccept.removeValue(forKey: sid) {
            c.resume(throwing: RelayError.closed)
        }
    }

    public func acceptStream(_ event: RelayV2PipeEvent) async throws -> RelayV2Stream {
        guard let sid = event.id, sid.utf8.count == 16, let peer = event.from, let body = event.body else {
            throw RelayError.invalid("invalid stream.open")
        }
        let remoteDesc = try identity.open(from: peer, kind: "stream.open", id: sid, body: body)
        let rx = try SecretStream(descriptor: remoteDesc)
        let tx = try SecretStream()
        let sealed = try identity.seal(to: peer, kind: "stream.accept", id: sid, value: tx.descriptor)
        let stream = RelayV2Stream(
            id: sid,
            peer: peer,
            identity: identity,
            tx: tx,
            rx: rx,
            sendFrame: { [weak self] frame in
                guard let self else { throw RelayError.closed }
                try await self.sendBinary(frame)
            },
            sendCloseEvent: { [weak self] in
                await self?.closeStream(id: sid)
            },
            sendCreditEvent: { [weak self] n in
                try? await self?.sendStreamCredit(streamID: sid, credit: n)
            }
        )
        streams[sid] = stream
        try await sendJSON([
            "type": "stream.accept",
            "space": space,
            "id": sid,
            "body": sealed,
        ])
        return stream
    }

    public func rejectStream(_ event: RelayV2PipeEvent) async {
        guard let sid = event.id else { return }
        await closeStream(id: sid)
    }

    public func closeStream(id sid: String) async {
        streams.removeValue(forKey: sid)
        try? await sendJSON([
            "type": "stream.close",
            "space": space,
            "id": sid,
        ])
    }

    public func close() async {
        closed = true
        readerTask?.cancel()
        readerTask = nil
        socket?.cancel()
        socket = nil
        await cleanupOnDisconnect(error: RelayError.closed)
    }

    private func sendJSON(_ obj: [String: Any]) async throws {
        guard let socket else { throw RelayError.closed }
        let data = try json(obj)
        try await socket.send(.string(String(decoding: data, as: UTF8.self)))
    }

    private func sendBinary(_ frame: Data) async throws {
        guard let socket else { throw RelayError.closed }
        try await socket.send(.data(frame))
    }

    private func handleBinary(_ frame: Data) async {
        guard let (sid, payload) = try? RelayV2Client.decodeStreamFrame(frame),
              let stream = streams[sid] else { return }
        await stream.deliver(cipher: payload)
    }

    private func handleEvent(_ ev: RelayV2PipeEvent) async -> Bool {
        switch ev.type {
        case "presence":
            if let reqID = ev.id, let c = pendingPresence.removeValue(forKey: reqID) {
                c.resume(returning: ev.peers ?? [])
                return false
            }
            return true
        case "stream.accept":
            if let sid = ev.id, let c = pendingAccept.removeValue(forKey: sid) {
                c.resume(returning: ev)
                return false
            }
            return false
        case "stream.credit":
            if let sid = ev.id, let st = streams[sid] {
                await st.handleCredit(ev.seq ?? 0)
            }
            return false
        case "stream.close":
            if let sid = ev.id {
                if let c = pendingAccept.removeValue(forKey: sid) {
                    c.resume(throwing: RelayError.closed)
                }
                if let st = streams.removeValue(forKey: sid) {
                    await st.remoteClosed()
                }
            }
            return false
        case "error":
            if let sid = ev.id, let c = pendingAccept.removeValue(forKey: sid) {
                c.resume(throwing: RelayError.invalid(ev.body ?? "stream error"))
                return false
            }
            if let reqID = ev.id, let c = pendingPresence.removeValue(forKey: reqID) {
                c.resume(throwing: RelayError.invalid(ev.body ?? "presence error"))
                return false
            }
            return true
        default:
            return true
        }
    }

    private func cleanupOnDisconnect(error: Error) async {
        let pAccept = pendingAccept; pendingAccept.removeAll()
        for (_, c) in pAccept { c.resume(throwing: error) }
        let pPres = pendingPresence; pendingPresence.removeAll()
        for (_, c) in pPres { c.resume(throwing: error) }
        let activeStreams = Array(streams.values); streams.removeAll()
        for st in activeStreams { await st.remoteClosed() }
    }
}
