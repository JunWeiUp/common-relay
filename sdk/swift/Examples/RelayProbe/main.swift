import Foundation
import CommonRelay

@main struct Probe {
    static func main() async throws {
        guard CommandLine.arguments.count == 2 else { fatalError("Usage: RelayProbe private-config.json") }
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))) as! [String: Any]
        // Group-ledger probe for scripts/group-interop.py; messaging runs over RelayV2Pipe.
        guard let action = object["group_action"] as? String else { fatalError("group_action required") }
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
    }
}
