// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "CommonRelay",
    platforms: [.macOS(.v13), .iOS(.v15)],
    products: [.library(name: "CommonRelay", targets: ["CommonRelay"]), .executable(name: "RelayProbe", targets: ["RelayProbe"])],
    dependencies: [.package(url: "https://github.com/jedisct1/swift-sodium.git", exact: "0.11.0")],
    targets: [
        .target(name: "CommonRelay", dependencies: [.product(name: "Clibsodium", package: "swift-sodium")]),
        .executableTarget(name: "RelayProbe", dependencies: ["CommonRelay"], path: "Examples/RelayProbe"),
        .testTarget(name: "CommonRelayTests", dependencies: ["CommonRelay"])
    ]
)
