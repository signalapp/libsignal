// swift-tools-version:5.0

//
// Copyright 2020-2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import PackageDescription

let rustBuildDir = "../target/debug/"
let autoImportSignalFfi = [
    // Use an undocumented, unstable flag to avoid mentioning SignalFfi in source files.
    // (Making this header accessible to both CocoaPods and SwiftPM is hard.)
    "-Xfrontend", "-import-module", "-Xfrontend", "SignalFfi"
]

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
            exclude: ["Logging.m"],
            swiftSettings: [.unsafeFlags(autoImportSignalFfi)]
        ),
        .testTarget(
            name: "SignalClientTests",
            dependencies: ["SignalClient"],
            swiftSettings: [.unsafeFlags(autoImportSignalFfi)],
            linkerSettings: [.unsafeFlags(["\(rustBuildDir)/libsignal_ffi.a"])]
        )
    ]
)
