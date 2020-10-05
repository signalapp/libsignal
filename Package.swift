// swift-tools-version:5.0
import PackageDescription

let package = Package(
    name: "SignalProtocol",
    products: [
        .library(
            name: "SignalProtocol",
            targets: ["SignalProtocol"]
        )
    ],
    dependencies: [],
    targets: [
        .systemLibrary(name: "SignalFfi", pkgConfig: "signal_ffi"),
        .target(name: "SignalProtocol", dependencies: ["SignalFfi"]),
        .testTarget(name: "SignalProtocolTests", dependencies: ["SignalProtocol"])
    ]
)
