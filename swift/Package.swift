// swift-tools-version:5.0

//
// Copyright 2020-2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

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
            exclude: ["Logging.m"]
        ),
        .testTarget(
            name: "SignalClientTests",
            dependencies: ["SignalClient"],
            linkerSettings: [.unsafeFlags(["\(rustBuildDir)/libsignal_ffi.a"])]
        )
    ]
)
