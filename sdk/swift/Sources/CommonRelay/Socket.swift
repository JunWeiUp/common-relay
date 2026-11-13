import Foundation
import Network

/// WebSocket transport on Network.framework.
///
/// `URLSessionWebSocketTask` is not used: on macOS 26 CFNetwork keeps every cancelled
/// WebSocket task (with its session, TLS trust and caches) reachable from a per-session
/// connection cache, even after `cancel` + `invalidateAndCancel`. A long-running client
/// that reconnects therefore leaked one full session per reconnect (~70 KB+ each).
/// `NWConnection` releases everything on `cancel()`.
final class RelaySocket: @unchecked Sendable {
    enum Message { case string(String), data(Data) }

    static let openTimeout: TimeInterval = 30
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "dev.common-relay.socket")
    private let lock = NSLock()
    private var cancelled = false

    init(request: URLRequest, maximumMessageSize: Int) throws {
        guard let url = request.url, let scheme = url.scheme?.lowercased(), scheme == "wss" || scheme == "ws" else { throw RelayError.invalid("WebSocket URL") }
        let options = NWProtocolWebSocket.Options()
        options.autoReplyPing = true
        options.maximumMessageSize = maximumMessageSize
        var headers: [(name: String, value: String)] = []
        for (name, value) in (request.allHTTPHeaderFields ?? [:]).sorted(by: { $0.key < $1.key }) {
            if name.caseInsensitiveCompare("Sec-WebSocket-Protocol") == .orderedSame {
                options.setSubprotocols(value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
            } else { headers.append((name, value)) }
        }
        options.setAdditionalHeaders(headers)
        let parameters: NWParameters = scheme == "wss" ? .tls : .tcp
        parameters.defaultProtocolStack.applicationProtocols.insert(options, at: 0)
        connection = NWConnection(to: .url(url), using: parameters)
    }

    /// Resolves once the HTTP upgrade succeeded. `waiting` (no route, refused, rejected
    /// upgrade) fails immediately so the caller's own reconnect policy stays in charge.
    func open(timeout: TimeInterval = RelaySocket.openTimeout) async throws {
        let once = Once()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let finish: (Error?) -> Void = { error in
                    guard once.claim() else { return }
                    if let error { continuation.resume(throwing: error) } else { continuation.resume() }
                }
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: finish(nil)
                    case .waiting(let error), .failed(let error): finish(error)
                    case .cancelled: finish(RelayError.closed)
                    default: break
                    }
                }
                queue.asyncAfter(deadline: .now() + timeout) { finish(NWError.posix(.ETIMEDOUT)) }
                if isCancelled { finish(RelayError.closed); return }
                connection.start(queue: queue)
            }
        } onCancel: { self.cancel() }
        connection.stateUpdateHandler = nil
    }

    func receive() async throws -> Message {
        while true {
            let (data, metadata) = try await receiveFrame()
            switch metadata?.opcode {
            case .text?: return .string(String(decoding: data, as: UTF8.self))
            case .binary?: return .data(data)
            case .close?: throw RelayError.closed
            default: continue // ping/pong/continuation are handled by the protocol stack
            }
        }
    }

    private func receiveFrame() async throws -> (Data, NWProtocolWebSocket.Metadata?) {
        try await withCheckedThrowingContinuation { continuation in
            connection.receiveMessage { data, context, isComplete, error in
                if let error { continuation.resume(throwing: error); return }
                let metadata = context?.protocolMetadata(definition: NWProtocolWebSocket.definition) as? NWProtocolWebSocket.Metadata
                if data == nil, metadata == nil, isComplete { continuation.resume(throwing: RelayError.closed); return }
                continuation.resume(returning: (data ?? Data(), metadata))
            }
        }
    }

    func send(_ message: Message) async throws {
        let opcode: NWProtocolWebSocket.Opcode, data: Data
        switch message {
        case .string(let text): opcode = .text; data = Data(text.utf8)
        case .data(let bytes): opcode = .binary; data = bytes
        }
        let context = NWConnection.ContentContext(identifier: "message", metadata: [NWProtocolWebSocket.Metadata(opcode: opcode)])
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, contentContext: context, isComplete: true, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }

    /// Sends a best-effort close frame, then tears the connection down. Idempotent.
    func cancel() {
        lock.lock(); let first = !cancelled; cancelled = true; lock.unlock()
        guard first else { return }
        let connection = connection
        guard connection.state == .ready else { connection.stateUpdateHandler = nil; connection.cancel(); return }
        let metadata = NWProtocolWebSocket.Metadata(opcode: .close); metadata.closeCode = .protocolCode(.goingAway)
        let context = NWConnection.ContentContext(identifier: "close", metadata: [metadata])
        connection.send(content: nil, contentContext: context, isComplete: true, completion: .contentProcessed { _ in connection.cancel() })
        queue.asyncAfter(deadline: .now() + 1) { connection.cancel() }
    }

    private var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }

    /// Network.framework reports a rejected upgrade as a generic abort. When opening fails,
    /// read the endpoint's plain HTTP status once so 401/403 still surface as an
    /// authentication failure (`NSURLErrorUserAuthenticationRequired`, as URLSession did).
    static func upgradeFailure(_ error: Error, request: URLRequest) async -> Error {
        if error is CancellationError { return error }
        if case RelayError.closed = error { return error }
        guard var components = request.url.flatMap({ URLComponents(url: $0, resolvingAgainstBaseURL: false) }) else { return error }
        components.scheme = components.scheme?.lowercased() == "ws" ? "http" : "https"
        guard let url = components.url else { return error }
        var probe = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        for (name, value) in request.allHTTPHeaderFields ?? [:] where name.caseInsensitiveCompare("Sec-WebSocket-Protocol") != .orderedSame { probe.setValue(value, forHTTPHeaderField: name) }
        guard let (_, response) = try? await RelayHTTP.session.data(for: probe), let status = (response as? HTTPURLResponse)?.statusCode else { return error }
        if status == 401 || status == 403 { return NSError(domain: NSURLErrorDomain, code: NSURLErrorUserAuthenticationRequired, userInfo: [NSLocalizedDescriptionKey: "relay upgrade rejected (\(status))"]) }
        return error
    }
}

private final class Once: @unchecked Sendable {
    private let lock = NSLock(); private var done = false
    func claim() -> Bool { lock.lock(); defer { lock.unlock() }; if done { return false }; done = true; return true }
}

/// One process-wide session for short relay HTTP calls (groups, upgrade probes). A session per
/// call cost a fresh connection context, TLS cache and delegate each time; requests carry
/// their own Authorization/Relay-Access headers, and cookies, caching and redirects are off.
enum RelayHTTP {
    static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil; configuration.httpShouldSetCookies = false
        configuration.urlCache = nil; configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.httpMaximumConnectionsPerHost = 2
        return URLSession(configuration: configuration, delegate: NoRedirectDelegate(), delegateQueue: nil)
    }()
}

private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
