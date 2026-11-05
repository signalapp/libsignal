// swift-tools-version:6.0

//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import PackageDescription

// This instructs Xcode to link against a local static library instead of the xcframework-sourced libsignal_ffi.
// This is useful for local development, to avoid the hassle of generating a new xcframework and replacing it on the app side.
let extraLinkerSettingsForUseAsLocalDependency: [LinkerSetting] = [
    // Uncomment this line for **simulator** builds.
    // .unsafeFlags(["\(Context.packageDirectory)/target/aarch64-apple-ios-sim/release/libsignal_ffi.a"]),

    // Uncomment this line for **device** builds.
    // .unsafeFlags(["\(Context.packageDirectory)/target/aarch64-apple-ios/release/libsignal_ffi.a"]),
]

// This is only used for local testing; the directory won't exist when used as a (remote) dependency.
let rustDebugBuildDir: String = {
    let packageDir = Context.packageDirectory
    if !packageDir.isEmpty {
        return packageDir + "/target/debug/"
    } else {
        return "target/debug/"
    }
}()

// This allows us to test the xcframework distribution of the Rust part of libsignal.
var testDependencies: [Target.Dependency] = ["LibSignalClient"]
var binaryTargets: [Target] = []
if let ffiXCFrameworkPath = Context.environment["LIBSIGNAL_FFI_XCFRAMEWORK"] {
    testDependencies.append("LibSignalFfi")
    binaryTargets.append(.binaryTarget(name: "LibSignalFfi", path: ffiXCFrameworkPath))
}

let package = Package(
    name: "LibSignalClient",
    platforms: [
        .macOS(.v10_15), .iOS(.v15),
    ],
    products: [
        .library(
            name: "LibSignalClient",
            targets: ["LibSignalClient"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.4.3")
    ],
    targets: [
        .systemLibrary(name: "SignalFfi", path: "swift/Sources/SignalFfi"),
        .target(
            name: "LibSignalClient",
            dependencies: ["SignalFfi"],
            path: "swift/Sources/LibSignalClient",
            swiftSettings: [.enableExperimentalFeature("StrictConcurrency")],
            linkerSettings: [
                .linkedLibrary("stdc++", .when(platforms: [.linux])),
            ] + extraLinkerSettingsForUseAsLocalDependency
        ),
        .testTarget(
            name: "LibSignalClientTests",
            dependencies: testDependencies,
            path: "swift/Tests/LibSignalClientTests",
            resources: [.process("Resources")],
            swiftSettings: [.enableExperimentalFeature("StrictConcurrency")],
            linkerSettings: [.unsafeFlags(["-L\(rustDebugBuildDir)"])]
        ),
    ] + binaryTargets
)
