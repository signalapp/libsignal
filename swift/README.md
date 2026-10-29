# Overview

This is a binding to the Signal client code in rust/, implemented on top of the C FFI produced by rust/bridge/ffi/. It's set up as a Swift Package, both for integration into the Signal iOS client and for local development.


# Use as a Swift Package

The Swift code is built from source as part of your app, but the Rust library is distributed separately as a prebuilt XCFramework, so you need two dependencies, both targeting the same release:

1. Add this repository as a package dependency pinned to the release, and link the `LibSignalClient` product.

        .package(url: "https://github.com/signalapp/libsignal", exact: "X.Y.Z")

2. In a package defined in the app, add a binary target for the XCFramework and link it into the same target(s) as `LibSignalClient`. You can find the checksum in the [GitHub Releases][] for the project.

        .binaryTarget(
            name: "LibSignalFfi",
            url: "https://build-artifacts.signal.org/libraries/libsignal-client-ios-build-vX.Y.Z.xcframework.zip",
            checksum: "..."
        )

If the two versions don't match, linking will fail with an undefined `signal_ffi_version_X_Y_Z` symbol.

[GitHub Releases]: https://github.com/signalapp/libsignal/releases


## Development with an App

Build the Rust library for each iOS target, then package the results as `target/LibSignalFfi.xcframework`:

    CARGO_BUILD_TARGET=x86_64-apple-ios swift/build_ffi.sh --release
    CARGO_BUILD_TARGET=aarch64-apple-ios-sim swift/build_ffi.sh --release
    CARGO_BUILD_TARGET=aarch64-apple-ios swift/build_ffi.sh --release
    swift/build_xcframework.py

If you only need the simulator, build just `aarch64-apple-ios-sim` and pass `--simulator-only` to `build_xcframework.py`. You can pass `--debug-level-logs` to `build_ffi.sh` to turn on debug- and verbose-level logs.

In the app, replace the libsignal package dependency with a local package pointing at this checkout. Then copy the XCFramework into the package that declares the `LibSignalFfi` binary target, and change that target to `.binaryTarget(name: "LibSignalFfi", path: "LibSignalFfi.xcframework")`. When you're done, revert both changes.

When exposing new APIs to Swift, you will need to add the `--generate-ffi` flag to your
`build_ffi.sh` invocation.


# Development as a Swift Package

1. Build the Rust library using `swift/build_ffi.sh`. The Swift Package.swift is configured to use the debug build of the Rust library.

2. Use `swift build` and `swift test` as usual.

To run the tests on an iOS simulator instead, use `swift/run_ios_tests.sh`. Extra arguments go to `xcodebuild`, for example `swift/run_ios_tests.sh -only-testing:LibSignalClientTests/PublicAPITests`. Any `LIBSIGNAL_TESTING_*` environment variables are forwarded to the tests.

When exposing new APIs to Swift, you will need to add the `--generate-ffi` flag to your
`build_ffi.sh` invocation.


# Benchmarks

The package in Benchmarks is set up for *relative* benchmarking on a build machine (rather than on iOS devices). This is mostly interesting to test that the bridging layer is not imposing undue overhead. Best results will come from testing on an Apple Silicon Mac, since that's closest in system libraries to an iOS device.

1. Build the Rust library using `swift/build_ffi.sh --release`.

2. `swift run -c release` from within the `swift/Benchmarks/` directory.

SwiftPM hides the executable in `.build/release/`, but you can find it there to run profiling tools on it.


# Catalyst Support

Mac Catalyst is not supported by this repository, but we've done experiments with it in the past. Rust targets for Catalyst are still in tier 3 support, so we use the experimental `-Zbuild-std` flag to build the standard library.

In order to compile for Catalyst you will need to:
* Install the standard library component with `rustup component add rust-src`
* Add the `--build-std` flag to your `build_ffi.sh` invocation

There may be other issues. For example, at one point the `cmake` crate had trouble compiling for Catalyst; you can try downgrading to version 0.1.48 if that's affecting you.
