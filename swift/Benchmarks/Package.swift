// swift-tools-version:5.2

//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import PackageDescription

let rustReleaseBuildDir = "../../target/release/"
let rustDebugBuildDir = "../../target/debug/"

let package = Package(
    name: "Benchmarks",
    platforms: [
        .macOS(.v10_15), .iOS(.v13),
    ],
    products: [
        .executable(name: "Benchmarks", targets: ["Benchmarks"]),
    ],
    dependencies: [
        .package(url: "https://github.com/google/swift-benchmark", from: "0.1.0"),
        .package(path: ".."),
    ],
    targets: [
        .target(
            name: "Benchmarks",
            dependencies: [
                .product(name: "Benchmark", package: "swift-benchmark"),
                .product(name: "LibSignalClient", package: "swift" /* the folder name, sigh */ ),
            ],
            linkerSettings: [
                .unsafeFlags(["-L\(rustReleaseBuildDir)"], .when(configuration: .release)),
                .unsafeFlags(["-L\(rustDebugBuildDir)"], .when(configuration: .debug)),
            ]
        ),
    ]
)
