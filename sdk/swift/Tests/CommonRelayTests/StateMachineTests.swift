import XCTest
@testable import CommonRelay

final class StateMachineTests: XCTestCase {
    actor MemBox {
        var draft: Data?
        var committed: Int?
        var trace: [String] = []
        func setDraft(_ d: Data?) { draft = d }
        func setCommitted(_ v: Int) { committed = v }
        func addTrace(_ s: String) { trace.append(s) }
    }

    func testDraftBeforeSendAndRecovery() async throws {
        let box = MemBox()
        let sm = RelayGroupStateMachine<Int>(
            saveDraft: { d in
                await box.addTrace("save")
                await box.setDraft(try d.encodeJSON())
            },
            loadDraft: {
                guard let raw = await box.draft else { return nil }
                return try RelayGroupDraft.decodeJSON(raw)
            },
            commit: { _, rev in
                await box.addTrace("commit")
                await box.setCommitted(rev)
            },
            clearDraft: { _ in
                await box.addTrace("clear")
                await box.setDraft(nil)
            }
        )

        let draft = RelayGroupDraft(
            draftID: "d1",
            op: "create",
            app: "clipy",
            group: "g1",
            device: "mac",
            secretKey: String(repeating: "00", count: 32),
            signSecretKey: String(repeating: "11", count: 32),
            token: String(repeating: "a", count: 64)
        )

        do {
            _ = try await sm.execute(draft) { _ in
                throw RelayError.closed
            }
            XCTFail("expected failure")
        } catch {}

        let pending = try await sm.pendingDraft()
        XCTAssertEqual(pending?.draftID, "d1")
        let committedBefore = await box.committed
        XCTAssertNil(committedBefore)

        let rev = try await sm.execute(draft) { _ in 3 }
        XCTAssertEqual(rev, 3)
        let pendingAfter = try await sm.pendingDraft()
        XCTAssertNil(pendingAfter)
        let trace = await box.trace
        XCTAssertEqual(trace, ["save", "save", "commit", "clear"])
    }

    func testDirectUpgradeRoundtrip() throws {
        XCTAssertEqual(relayDirectUpgradeTopic, "relay.direct.v1")
        let msg = RelayDirectUpgradeMessage(
            op: "offer",
            session: "s1",
            candidates: ["192.168.1.9:47899"],
            nonce: "cafe"
        )
        let raw = try msg.encode()
        XCTAssertEqual(try RelayDirectUpgradeMessage.decode(raw), msg)
        XCTAssertThrowsError(try RelayDirectUpgradeMessage(op: "bad", session: "s1").encode())
    }
}
