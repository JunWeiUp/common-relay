import Foundation

/// Immutable serialized wire value. Decoding produces a fresh, thread-local object graph.
public struct RelayEvent: Sendable {
    private let wire: Data
    private let payload: Data?
    init(_ object: [String: Any]) throws {
        var metadata = object
        payload = metadata.removeValue(forKey: "data") as? Data
        wire = try json(metadata)
    }
    public var object: [String: Any] {
        var result = (try? dictionary(wire)) ?? [:]
        if let payload { result["data"] = payload }
        return result
    }
    public subscript(_ key: String) -> Any? { key == "data" ? payload : object[key] }
}
