import Foundation
import CommonRelay

@main struct Probe {
    static func main() async throws {
        guard CommandLine.arguments.count == 2 else { fatalError("Usage: RelayProbe private-config.json") }
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))) as! [String: Any]
        if let action = object["group_action"] as? String {
            let g = RelayGroups(config:object,allowLocalTest:true);var result: Any = [:]
            switch action {
            case "rename": try await g.rename(device:object["device"] as! String,name:"Updated device")
            case "leave": try await g.prepareExit();try await g.exit()
            case "disband": try await g.prepareExit(disband:true);try await g.exit()
            case "create": g.config.removeValue(forKey:"group");try g.prepareCreate(groupName:"My devices",deviceName:"Creator");try await g.create()
            case "join": var invitation = object["invitation"] as? [String:Any] ?? [:];if let link=object["invitation_link"] as? String { invitation=try await g.resolveInvitation(link) };try await g.join(invitation,name:object["device"] as! String)
            case "finish": result = try await g.finishJoin()
            case "invite": result = try await g.invite(mode:object["invite_mode"] as? String ?? "manual",compact:object["compact"] as? Bool ?? false)
            case "approve": try await g.approve(object["invitation"] as! [String:Any],request:object["request"] as! [String:Any])
            case "remove": try await g.remove(device:object["remove"] as! String)
            default: result = try await g.refresh()
            }
            g.config["result"] = result
            try JSONSerialization.data(withJSONObject:g.config).write(to:URL(fileURLWithPath:CommandLine.arguments[1]),options:.atomic)
            return
        }
        let peers = try (object["trusted_peers"] as! [String: String]).mapValues { try Data(relayHex: $0) }
        let identity = try RelayIdentity(app: object["app"] as! String, group: object["group"] as! String, device: object["device"] as! String, secretKey: Data(relayHex: object["secret_key"] as! String), trustedPeers: peers)
        let journal = try (object["state_path"] as? String).map { try RelayJournal(directory: URL(fileURLWithPath: $0)) }
        let client = RelayClient(identity: identity, journal: journal)
        let events = try await client.connect(url: URL(string: object["url"] as! String)!, token: object["token"] as! String, allowLocalTest: object["allow_local_test"] as? Bool ?? false)
        print("READY")
        for try await event in events {
            if object["group_notice_only"] as? Bool == true, event["type"] as? String == "group.changed" {
                print("GROUP_NOTICE \(event["revision"] as? Int ?? -1)")
                await client.close()
                return
            }
            if event["type"] as? String == "stream.open" {
                Task {
                    do {
                        let stream = try await client.acceptStream(event)
                        while !(await stream.receivedFinal) { let data = try await stream.receive(); try await stream.send(data, final: await stream.receivedFinal) }
                    } catch { print("STREAM_FAILED") }
                }
            } else if event["type"] as? String == "message", let from = event["from"] as? String, let data = event["data"] as? Data {
                _ = try await client.message(to: from, data: data, offline: event["offline"] as? Bool ?? false)
                if event["offline"] as? Bool == true { try await client.acknowledge(id: event["id"] as! String, from: from, offline: true) }
            }
        }
    }
}
