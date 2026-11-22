import XCTest
import Clibsodium
@testable import CommonRelay
final class InvitationLinksTests: XCTestCase {
 private func vectors() throws -> (v: [String:Any], key: Data, invitation: [String:Any], link: String, withPassword: String) {
  let v=try ProtocolVectors.load("invitation-link-vectors.json"),key=try Data(relayHex:v["key"] as! String)
  return (v,key,v["invitation"] as! [String:Any],v["link"] as! String,v["link_with_password"] as! String)
 }
 func testSharedPacketAndTampering() throws {
  let (v,key,inv,link,_)=try vectors(),packet=v["packet"] as! String
  XCTAssertTrue(NSDictionary(dictionary:try RelayInvitationLinks.open(packet,key:key)).isEqual(to:inv))
  // The sealed bytes are exactly packet_plaintext.
  let raw=try XCTUnwrap(Data(base64Encoded:packet)),cipher=Array(raw.dropFirst(24));var plain=[UInt8](repeating:0,count:cipher.count-16)
  XCTAssertEqual(crypto_secretbox_open_easy(&plain,cipher,UInt64(cipher.count),Array(raw.prefix(24)),Array(key)),0)
  XCTAssertEqual(String(decoding:plain,as:UTF8.self),v["packet_plaintext"] as? String)
  XCTAssertEqual(try RelayInvitationLinks.readToken(key),v["read_token"] as? String)
  XCTAssertEqual(RelayGroups.digest(Data((v["read_token"] as! String).utf8)),v["read_hash"] as? String)
  XCTAssertEqual(try RelayInvitationLinks.make(inv,key:key),link);XCTAssertEqual(link.count,v["link_length"] as? Int)
  let parsed=try RelayInvitationLinks.parse(link);XCTAssertEqual(parsed.url,inv["url"] as? String);XCTAssertEqual(parsed.id,inv["id"] as? String);XCTAssertEqual(parsed.key,key)
  // Swift dictionaries do not preserve key order, so a fresh seal is checked by round-trip, not byte equality.
  let own=try RelayInvitationLinks.seal(inv,key:key,nonce:Data(relayHex:v["nonce"] as! String));XCTAssertTrue(NSDictionary(dictionary:try RelayInvitationLinks.open(own,key:key)).isEqual(to:inv))
  XCTAssertThrowsError(try RelayInvitationLinks.open(packet,key:Data(repeating:0,count:32)))
  for bad in v["invalid_links"] as! [String] { XCTAssertThrowsError(try RelayInvitationLinks.parse(bad),bad) }
 }
 func testRemovedV1FormsAreRejected() throws {
  let (_,key,inv,link,_)=try vectors()
  var old=inv;old["url"]="wss://relay.example.com/relay/v1/ws"
  XCTAssertThrowsError(try RelayInvitationLinks.make(old,key:key))
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
