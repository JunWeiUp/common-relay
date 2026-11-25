import XCTest
@testable import CommonRelay

final class V2PipeStreamTests: XCTestCase {
    private actor CloseRecorder {
        var count = 0
        func mark() { count += 1 }
    }

    func testBuffersPreAttachFramesAndSendsCloseOnDecryptError() async throws {
        let aliceSk = RelayIdentity.generateSecretKey()
        let bobSk = RelayIdentity.generateSecretKey()
        let alicePub = try RelayIdentity(app: "clipy", group: "grp", device: "alice", secretKey: aliceSk, trustedPeers: [:]).publicKey
        let bobPub = try RelayIdentity(app: "clipy", group: "grp", device: "bob", secretKey: bobSk, trustedPeers: [:]).publicKey

        let alice = try RelayIdentity(app: "clipy", group: "grp", device: "alice", secretKey: aliceSk, trustedPeers: ["bob": bobPub])
        let bob = try RelayIdentity(app: "clipy", group: "grp", device: "bob", secretKey: bobSk, trustedPeers: ["alice": alicePub])

        let sid = "0123456789abcdef"
        let bobTx = try SecretStream()
        let aliceTx = try SecretStream()
        let closeRecorder = CloseRecorder()

        // Alice has rx == nil initially (before stream.accept attaches receiver).
        let aliceStream = RelayV2Stream(
            id: sid,
            peer: "bob",
            identity: alice,
            tx: aliceTx,
            rx: nil,
            sendFrame: { _ in },
            sendCloseEvent: { await closeRecorder.mark() }
        )

        // Bob encrypts 3 frames before Alice attaches receiver.
        var ciphers: [Data] = []
        for i in 0..<3 {
            let aad = try bob.aad(from: "bob", to: "alice", kind: "stream", id: sid, sequence: UInt64(i))
            let cipher = try bobTx.push(Data("msg-\(i)".utf8), aad: aad, final: false)
            ciphers.append(cipher)
        }
        for c in ciphers {
            await aliceStream.deliver(cipher: c)
        }

        // Now attach receiver; buffered frames must drain in order without dropping seq 0.
        let aliceRx = try SecretStream(descriptor: bobTx.descriptor)
        await aliceStream.attachReceiver(aliceRx)

        var received: [String] = []
        for _ in 0..<3 {
            let plain = try await aliceStream.receive()
            received.append(String(decoding: plain, as: UTF8.self))
        }
        XCTAssertEqual(received, ["msg-0", "msg-1", "msg-2"])

        // Deliver a corrupted ciphertext -> must notify peer with stream.close immediately.
        await aliceStream.deliver(cipher: Data(repeating: 0xAA, count: 32))
        try await Task.sleep(nanoseconds: 50_000_000)
        let closeCount = await closeRecorder.count
        XCTAssertEqual(closeCount, 1)

        // Calling close() afterwards must not send a duplicate close event.
        await aliceStream.close()
        let closeCountAfter = await closeRecorder.count
        XCTAssertEqual(closeCountAfter, 1)
    }
}
