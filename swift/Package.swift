// swift-tools-version:5.0
import PackageDescription

let rustBuildDir = "../target/debug/"

let package = Package(
    name: "SignalClient",
    products: [
        .library(
            name: "SignalClient",
            targets: ["SignalClient"]
        )
    ],
    dependencies: [],
    targets: [
        .systemLibrary(name: "SignalFfi"),
        .target(
            name: "SignalClient",
            dependencies: ["SignalFfi"],
            swiftSettings: [.unsafeFlags(["-I", rustBuildDir])]
        ),
        .testTarget(
            name: "SignalClientTests",
            dependencies: ["SignalClient"],
            swiftSettings: [.unsafeFlags(["-I", rustBuildDir])],
            linkerSettings: [.unsafeFlags(["\(rustBuildDir)/libsignal_ffi.a"])]
        )
    ]
)
