// swift-tools-version:5.0

//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import PackageDescription

let rustBuildDir = "../target/debug/"

let package = Package(
    name: "LibSignalClient",
    products: [
        .library(
            name: "LibSignalClient",
            targets: ["LibSignalClient"]
        )
    ],
    dependencies: [],
    targets: [
        .systemLibrary(name: "SignalFfi"),
        .target(
            name: "LibSignalClient",
            dependencies: ["SignalFfi"],
            exclude: ["Logging.m"]
        ),
        .testTarget(
            name: "LibSignalClientTests",
            dependencies: ["LibSignalClient"],
            linkerSettings: [.unsafeFlags(["-L\(rustBuildDir)"])]
        )
    ]
)
