// swift-tools-version:5.0
import PackageDescription

let rustBuildDir = "../target/debug/"

let package = Package(
    name: "SignalClient",
    products: [
        .library(
            name: "SignalClient",
            targets: ["SignalProtocol"]
        )
    ],
    dependencies: [],
    targets: [
        .systemLibrary(name: "SignalFfi"),
        .target(
            name: "SignalProtocol",
            dependencies: ["SignalFfi"],
            swiftSettings: [.unsafeFlags(["-I", rustBuildDir])]
        ),
        .testTarget(
            name: "SignalProtocolTests",
            dependencies: ["SignalProtocol"],
            swiftSettings: [.unsafeFlags(["-I", rustBuildDir])],
            linkerSettings: [.unsafeFlags(["\(rustBuildDir)/libsignal_ffi.a"])]
        )
    ]
)
