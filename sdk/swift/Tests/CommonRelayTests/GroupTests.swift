import XCTest
@testable import CommonRelay
final class GroupTests: XCTestCase {
    func testSharedMembershipVectors() throws {
        let v = try ProtocolVectors.load("group-vectors.json"), config = v["config"] as! [String:Any], manager = v["manager"] as! [String:Any]
        let groups = RelayGroups(config:config), first = v["initial"] as! [String:Any], added = v["approved"] as! [String:Any], removed = v["removed"] as! [String:Any]
        XCTAssertEqual(try groups.member(name:"Mac")["signing_key"] as? String,manager["signing_key"] as? String)
        try RelayGroups.verify(v["self_service"] as! [String:Any],key:manager["signing_key"] as! String)
        try RelayGroups.verify(first,key:manager["signing_key"] as! String)
        _ = try groups.advance(first,added);_ = try groups.advance(added,removed)
        _ = try groups.advance(added,v["renamed"] as! [String:Any]);XCTAssertThrowsError(try groups.advance(added,v["unauthorized_rename"] as! [String:Any]))
        _ = try groups.advance(added,v["left"] as! [String:Any]);_ = try groups.advance(added,v["disbanded"] as! [String:Any])
        XCTAssertThrowsError(try groups.advance(added,v["unauthorized_disband"] as! [String:Any]))
        XCTAssertThrowsError(try groups.advance(first,removed))
        let automatic = v["auto_admission"] as! [String:Any]
        _ = try groups.advance(first,automatic["approved"] as! [String:Any])
        for item in automatic["invalid"] as! [[String:Any]] { XCTAssertThrowsError(try groups.advance(first,item["entry"] as! [String:Any]),item["case"] as! String) }
        let strict = v["strict_payload"] as! [String:Any]
        for item in strict["valid"] as! [[String:Any]] { XCTAssertNoThrow(try groups.advance(added,item["entry"] as! [String:Any]),item["case"] as! String) }
        for item in strict["invalid"] as! [[String:Any]] { XCTAssertThrowsError(try groups.advance(added,item["entry"] as! [String:Any]),item["case"] as! String) }
        for item in strict["invalid_auto"] as! [[String:Any]] { XCTAssertThrowsError(try groups.advance(first,item["entry"] as! [String:Any]),item["case"] as! String) }
        var tampered = added;tampered["signature"] = String(repeating:"00",count:64);XCTAssertThrowsError(try groups.advance(first,tampered))
    }

    func testEntryHashesAndLinks() throws {
        let v = try ProtocolVectors.load("group-vectors.json"), hashes = v["entry_hashes"] as! [String:Any]
        let cases = hashes["cases"] as! [[String:Any]], links = hashes["links"] as! [[String:Any]]
        XCTAssertFalse(cases.isEmpty); XCTAssertFalse(links.isEmpty)
        for item in cases {
            let path = item["entry"] as! String, entry = try XCTUnwrap(ProtocolVectors.lookup(v, path), path)
            XCTAssertEqual(RelayGroups.digest(try RelayGroups.payload(entry)), item["payload_sha256"] as? String, path)
            let valid = (try? RelayGroups.verify(entry, key: item["verify_key"] as! String)) != nil
            XCTAssertEqual(valid, item["signature_valid"] as? Bool, path)
        }
        for link in links {
            let base = try XCTUnwrap(ProtocolVectors.lookup(v, link["base"] as! String)), next = try XCTUnwrap(ProtocolVectors.lookup(v, link["next"] as! String))
            let decoded = try dictionary(try RelayGroups.payload(next))
            XCTAssertEqual(decoded["previous"] as? String, RelayGroups.digest(try RelayGroups.payload(base)), "\(link)")
        }
    }
}
