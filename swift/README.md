# Overview

This is a binding to the Signal client code in rust/, implemented on top of the C FFI produced by rust/bridge/ffi/. It's set up as a CocoaPod for integration into the Signal iOS client and as a Swift Package for local development.


# Use as CocoaPod

1. Make sure you are using `use_frameworks!` in your Podfile. SignalClient is a Swift pod and as such cannot be compiled as a plain library.

2. Add 'SignalClient' and 'SignalCoreKit' as dependencies in your Podfile:

        pod 'SignalClient', git: 'https://github.com/signalapp/libsignal-client.git'
        pod 'SignalCoreKit', git: 'https://github.com/signalapp/SignalCoreKit.git'

3. Use `pod install` or `pod update` to build the Rust library for all targets. You may be prompted to install Rust dependencies (`cbindgen`, `rust-src`, `xargo`).

4. Build as usual. The Rust library will automatically be linked into the built SignalClient.framework.


## Development as a CocoaPod

Instead of a git-based dependency, use a path-based dependency to treat SignalClient as a development pod. Since [`prepare_command`s][pc] are not run for path-based dependencies, you will need to build the Rust library yourself. (Xcode should prompt you to do this if you forget.)

    CARGO_BUILD_TARGET=x86_64-apple-ios swift/build_ffi.sh --release

The CocoaPod is configured to use the release build of the Rust library.

If validating SignalClient locally, use the following invocation:

    XCODE_XCCONFIG_FILE=swift/PodLibLint.xcconfig pod lib lint \
      --platforms=ios \
      --include-podspecs=../SignalCoreKit/SignalCoreKit.podspec \
      --skip-import-validation \
      --verbose

You will also need to have [SignalCoreKit][] checked out; the above command assumes you have checked it out as a sibling directory to libsignal-client.

When exposing new APIs to Swift, you will need to add the `--generate-ffi` flag to your
`build_ffi.sh` invocation.

[pc]: https://guides.cocoapods.org/syntax/podspec.html#prepare_command
[SignalCoreKit]: https://github.com/signalapp/SignalCoreKit


# Development as a Swift Package

1. Build the Rust library using `swift/build_ffi.sh`. The Swift Package.swift is configured to use the debug build of the Rust library.

2. Use `swift build` and `swift test` as usual from within the `swift/` directory.

When exposing new APIs to Swift, you will need to add the `--generate-ffi` flag to your
`build_ffi.sh` invocation.


## Use as a Swift Package

...is not supported. In theory we could make this work through the use of a custom pkg-config file and requiring clients to set `PKG_CONFIG_PATH` (or install the Rust build products), but since Signal itself does not use this configuration it's considered extra maintenance burden. Development as a package is supported as a lightweight convenience (as well as a cross-platform one), but the CocoaPods build is considered the canonical one.

# M1 Simulator and Catalyst

Rust targets for both the M1 Simulator and Catalyst are still in tier 3 support, so we use `xargo` to build the standard library. 

In order to compile for these platforms you will need to:
* Install Xargo with `cargo install xargo`
* Install the standard library component with `rustup component add rust-src`
* If not using Cocoapods, add the `--use-xargo` flag to your `build_ffi.sh` invocation
