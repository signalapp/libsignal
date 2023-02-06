# Overview

This is a binding to the Signal client code in rust/, implemented on top of the C FFI produced by rust/bridge/ffi/. It's set up as a CocoaPod for integration into the Signal iOS client and as a Swift Package for local development.


# Use as CocoaPod

1. Make sure you are using `use_frameworks!` in your Podfile. LibSignalClient is a Swift pod and as such cannot be compiled as a plain library.

2. Add 'LibSignalClient' and 'SignalCoreKit' as dependencies in your Podfile, as well as the prebuild checksum for the latest release. You can find the checksum in the [GitHub Releases][] for the project.

        pod 'LibSignalClient', git: 'https://github.com/signalapp/libsignal.git'
        pod 'SignalCoreKit', git: 'https://github.com/signalapp/SignalCoreKit.git'
        ENV['LIBSIGNAL_FFI_PREBUILD_CHECKSUM'] = '...'

3. Use `pod install` or `pod update` to build the Rust library for all targets. You may be prompted to install Rust dependencies (`cbindgen`, `rust-src`).

4. Build as usual. The Rust library will automatically be linked into the built LibSignalClient.framework.

[GitHub Releases]: https://github.com/signalapp/libsignal/releases


## Development as a CocoaPod

Instead of a git-based dependency, use a path-based dependency to treat LibSignalClient as a development pod. Since [`prepare_command`s][pc] are not run for path-based dependencies, you will need to build the Rust library yourself. (Xcode should prompt you to do this if you forget.)

    CARGO_BUILD_TARGET=x86_64-apple-ios swift/build_ffi.sh --release

The CocoaPod is configured to use the release build of the Rust library.

If validating LibSignalClient locally, use the following invocation:

    pod lib lint \
      --platforms=ios \
      --include-podspecs=../SignalCoreKit/SignalCoreKit.podspec \
      --skip-import-validation \
      --verbose

You will also need to have [SignalCoreKit][] checked out; the above command assumes you have checked it out as a sibling directory to libsignal.

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

# Catalyst Support

Rust targets for Mac Catalyst are still in tier 3 support, so we use the experimental `-Zbuild-std` flag to build the standard library.

In order to compile for these platforms you will need to:
* Install the standard library component with `rustup component add rust-src`
* If not using Cocoapods, add the `--build-std` flag to your `build_ffi.sh` invocation
