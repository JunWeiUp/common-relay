import Foundation
@testable import CommonRelay

/// Shared protocol vectors live in `<repo>/protocol/v2/`.
enum ProtocolVectors {
    static let directory: URL = {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        return root.appendingPathComponent("protocol/v2")
    }()
    static func load(_ name: String) throws -> [String: Any] {
        try dictionary(Data(contentsOf: directory.appendingPathComponent(name)))
    }
    /// Resolves a dotted path such as `auto_admission.approved`.
    static func lookup(_ root: [String: Any], _ path: String) -> [String: Any]? {
        var node: Any? = root
        for part in path.split(separator: ".") { node = (node as? [String: Any])?[String(part)] }
        return node as? [String: Any]
    }
}
