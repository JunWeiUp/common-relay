import XCTest
@testable import CommonRelay

final class V2ClientTests: XCTestCase {
    func testProtocolV2VectorsAndRouting() throws {
        XCTAssertEqual(
            RelayV2Client.hashSecret("common-relay-v2-vector-secret"),
            "adc39f9ca5ad73f3c7e6aa2af6008c4e86e09e0d0c3596226b6b44ea82b20413"
        )
        let payload = Data("ZIP_STREAM_CHUNK_DATA".utf8)
        let frame = try RelayV2Client.encodeStreamFrame(streamID: "0123456789abcdef", payload: payload)
        let hex = frame.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(hex, "303132333435363738396162636465665a49505f53545245414d5f4348554e4b5f44415441")
        let (sid, decoded) = try RelayV2Client.decodeStreamFrame(frame)
        XCTAssertEqual(sid, "0123456789abcdef")
        XCTAssertEqual(decoded, payload)

        XCTAssertEqual(RelayV2Client.chooseRoute(lanReachable: true, peerOnline: true), .lanDirect)
        XCTAssertEqual(RelayV2Client.chooseRoute(lanReachable: false, peerOnline: true), .pipeStream)
        XCTAssertEqual(RelayV2Client.chooseRoute(lanReachable: false, peerOnline: false), .boxEphemeral)

        let c = try RelayV2Client(baseURL: "https://relay.example/", accessPassword: "acc", token: "tok")
        XCTAssertEqual(c.wsURL.absoluteString, "wss://relay.example/v2/ws")
        XCTAssertThrowsError(try RelayV2Client(baseURL: "http://relay.example", accessPassword: "acc", token: "tok"))
    }
}
