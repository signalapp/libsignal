// swift-tools-version:5.0
import PackageDescription

let package = Package(
    name: "SwiftSignal",
    products: [
        .library(
            name: "SwiftSignal",
            targets: ["SwiftSignal"]
        )
    ],
    dependencies: [],
    targets: [
        .systemLibrary(name: "SignalFfi"),
        .target(name: "SwiftSignal", dependencies: ["SignalFfi"]),
        .testTarget(name: "SwiftSignalTests", dependencies: ["SwiftSignal"])
    ]
)
