// swift-tools-version:6.0

//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import PackageDescription

// This is only used for local builds; the directory won't exist when used as a (remote) dependency.
let rustBuildDir: String = {
    let manifestPath = #filePath
    if let lastDirectorySep = manifestPath.lastIndex(of: "/") {
        return manifestPath[...lastDirectorySep] + "target/debug/"
    } else {
        return "target/debug/"
    }
}()

let package = Package(
    name: "LibSignalClient",
    platforms: [
        .macOS(.v10_15), .iOS(.v13),
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
                .linkedLibrary("stdc++", .when(platforms: [.linux]))
            ]
        ),
        .testTarget(
            name: "LibSignalClientTests",
            dependencies: ["LibSignalClient"],
            path: "swift/Tests/LibSignalClientTests",
            resources: [.process("Resources")],
            swiftSettings: [.enableExperimentalFeature("StrictConcurrency")],
            linkerSettings: [.unsafeFlags(["-L\(rustBuildDir)"])]
        ),
    ]
)
