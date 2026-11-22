import XCTest
@testable import CommonRelay
final class InvitationLinksTests: XCTestCase {
 /// Loads the shared vectors as /v2 links. Packets are opaque ciphertext; only the
 /// invitation URL and the link path depend on the endpoint family.
 private func vectors() throws -> (v: [String:Any], key: Data, invitation: [String:Any], link: String, withPassword: String) {
  let file=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("protocol/invitation-link-vectors.json")
  let v=try dictionary(Data(contentsOf:file)),key=try Data(relayHex:v["key"] as! String)
  var inv=try RelayInvitationLinks.open(v["packet"] as! String,key:key)
  inv["url"]=(inv["url"] as! String).replacingOccurrences(of:"/relay/v1/ws",with:"/v2/ws")
  func v2(_ link: String) -> String { link.contains("/v2/i/") ? link : link.replacingOccurrences(of:".com/i/",with:".com/v2/i/") }
  return (v,key,inv,v2(v["link"] as! String),v2(v["link_with_password"] as! String))
 }
 func testSharedPacketAndTampering() throws {
  let (v,key,inv,link,_)=try vectors(),packet=v["packet"] as! String
  XCTAssertEqual(try RelayInvitationLinks.readToken(key),v["read_token"] as? String)
  XCTAssertEqual(try RelayInvitationLinks.make(inv,key:key),link);XCTAssertEqual(try RelayInvitationLinks.parse(link).url,inv["url"] as? String)
  let own=try RelayInvitationLinks.seal(inv,key:key,nonce:Data(relayHex:v["nonce"] as! String));XCTAssertTrue(NSDictionary(dictionary:try RelayInvitationLinks.open(own,key:key)).isEqual(to:inv))
  XCTAssertThrowsError(try RelayInvitationLinks.open(packet,key:Data(repeating:0,count:32)));XCTAssertThrowsError(try RelayInvitationLinks.parse(link+"="));XCTAssertThrowsError(try RelayInvitationLinks.parse(link.replacingOccurrences(of:"relay.example.com",with:"user@relay.example.com")))
 }
 func testRemovedV1FormsAreRejected() throws {
  let (_,key,inv,link,_)=try vectors()
  var old=inv;old["url"]="wss://relay.example.com/relay/v1/ws"
  XCTAssertThrowsError(try RelayInvitationLinks.make(old,key:key))
  XCTAssertThrowsError(try RelayInvitationLinks.parse(link.replacingOccurrences(of:"/v2/i/",with:"/i/")))
  XCTAssertEqual(try RelayInvitationLinks.parse(link.replacingOccurrences(of:"relay.example.com",with:"127.0.0.1"),allowLocalTest:true).url,"ws://127.0.0.1/v2/ws")
 }
 func testAccessPasswordInFragment() throws {
  let (v,key,inv,link,withPassword)=try vectors(),password=v["access_password"] as! String
  XCTAssertEqual(try RelayInvitationLinks.make(inv,key:key,password:password),withPassword)
  let parsed=try RelayInvitationLinks.parse(withPassword);XCTAssertEqual(parsed.password,password);XCTAssertEqual(parsed.key,key);XCTAssertEqual(parsed.url,inv["url"] as? String)
  XCTAssertNil(try RelayInvitationLinks.parse(link).password)
  for suffix in v["invalid_link_suffixes"] as! [String] { XCTAssertThrowsError(try RelayInvitationLinks.parse(link+suffix),suffix) }
 }
}
