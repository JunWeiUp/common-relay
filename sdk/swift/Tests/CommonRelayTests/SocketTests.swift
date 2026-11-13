import XCTest
import Network
@testable import CommonRelay

/// Loopback-only: an in-process NWListener WebSocket server, no relay server or real network.
private final class HeaderBox: @unchecked Sendable { var values: [String: String] = [:] }

final class SocketTests: XCTestCase {
    private final class Server: @unchecked Sendable {
        let listener: NWListener
        let queue = DispatchQueue(label: "socket-tests.server")
        private(set) var box: HeaderBox!
        var headers: [String: String] { box.values }
        var connections: [NWConnection] = []
        init(reject: Bool = false) throws {
            let options = NWProtocolWebSocket.Options()
            options.autoReplyPing = true
            let box = HeaderBox()
            options.setClientRequestHandler(queue) { protocols, headers in
                for (name, value) in headers { box.values[name.lowercased()] = value }
                box.values["subprotocols"] = protocols.joined(separator: ",")
                return NWProtocolWebSocket.Response(status: reject ? .reject : .accept, subprotocol: protocols.first, additionalHeaders: nil)
            }
            let parameters = NWParameters.tcp
            parameters.defaultProtocolStack.applicationProtocols.insert(options, at: 0)
            listener = try NWListener(using: parameters, on: .any)
            self.box = box
            listener.newConnectionHandler = { [unowned self] connection in
                connections.append(connection); connection.start(queue: queue); echo(connection)
            }
        }
        func start() async throws -> UInt16 {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
                listener.stateUpdateHandler = { [unowned self] state in
                    if case .ready = state { continuation.resume(returning: listener.port!.rawValue); listener.stateUpdateHandler = nil }
                    if case .failed(let error) = state { continuation.resume(throwing: error); listener.stateUpdateHandler = nil }
                }
                listener.start(queue: queue)
            }
        }
        private func echo(_ connection: NWConnection) {
            connection.receiveMessage { [weak self] data, context, _, error in
                guard error == nil, let self, let context, let data else { return }
                connection.send(content: data, contentContext: context, isComplete: true, completion: .contentProcessed { _ in })
                self.echo(connection)
            }
        }
        func stop() { listener.cancel(); connections.forEach { $0.cancel() } }
    }

    private func request(_ port: UInt16) throws -> URLRequest {
        try RelayClient.upgradeRequest(url: URL(string: "ws://127.0.0.1:\(port)/relay/v1/ws")!, token: "tok", password: "access-pass")
    }

    func testUpgradeHeadersAndEcho() async throws {
        let server = try Server(); let port = try await server.start(); defer { server.stop() }
        let socket = try RelaySocket(request: try request(port), maximumMessageSize: 270336)
        try await socket.open(timeout: 5)
        XCTAssertEqual(server.queue.sync { server.headers["authorization"] }, "Bearer tok")
        XCTAssertEqual(server.queue.sync { server.headers["relay-access"] }, "access-pass")
        XCTAssertEqual(server.queue.sync { server.headers["subprotocols"] }, "common-relay.v1")
        try await socket.send(.string("hello"))
        guard case .string(let text) = try await socket.receive() else { return XCTFail("expected text") }
        XCTAssertEqual(text, "hello")
        let payload = Data((0..<65_000).map { UInt8($0 & 0xff) })
        try await socket.send(.data(payload))
        guard case .data(let echoed) = try await socket.receive() else { return XCTFail("expected binary") }
        XCTAssertEqual(echoed, payload)
        socket.cancel()
        do { _ = try await socket.receive(); XCTFail("receive after cancel must throw") } catch {}
    }

    func testRejectedUpgradeFails() async throws {
        let server = try Server(reject: true); let port = try await server.start(); defer { server.stop() }
        let socket = try RelaySocket(request: try request(port), maximumMessageSize: 1024)
        do { try await socket.open(timeout: 5); XCTFail("rejected upgrade must not open") } catch {}
        socket.cancel()
    }

    func testCancelledSocketsAreReleased() async throws {
        let server = try Server(); let port = try await server.start(); defer { server.stop() }
        weak var released: RelaySocket?
        for _ in 0..<5 {
            let socket = try RelaySocket(request: try request(port), maximumMessageSize: 1024)
            try await socket.open(timeout: 5); socket.cancel(); released = socket
        }
        for _ in 0..<40 where released != nil { try await Task.sleep(nanoseconds: 50_000_000) }
        XCTAssertNil(released, "cancelled RelaySocket must not stay reachable")
    }

    func testOpenFailsFastWhenNothingListens() async throws {
        let socket = try RelaySocket(request: try request(1), maximumMessageSize: 1024)
        let start = Date()
        do { try await socket.open(timeout: 5); XCTFail("must fail") } catch {}
        XCTAssertLessThan(Date().timeIntervalSince(start), 4)
    }
}
