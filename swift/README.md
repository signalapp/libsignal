# Overview

This is a binding to the Signal client code in rust/, implemented on top of the C FFI in rust/bridge/ffi/. It's set up as a CocoaPod for integration into the Signal iOS client and as a Swift Package for local development.


# Use as CocoaPod

1. Make sure you are using `use_frameworks!` in your Podfile. SignalClient is a Swift pod and as such cannot be compiled as a plain library.

2. Add 'SignalClient' as a dependency in your Podfile:

        pod 'SignalClient', git: 'https://github.com/signalapp/libsignal-client.git'

3. Build as usual. The Rust library will be built as a script phase and linked into the built SignalClient.framework.

## Development as a CocoaPod

Instead of a git-based dependency, use a path-based dependency to treat SignalClient as a development pod. If validating SignalClient locally, use the following invocation:

    XCODE_XCCONFIG_FILE=swift/PodLibLint.xcconfig pod lib lint \
      --platforms=ios \
      --include-podspecs=../SignalCoreKit/SignalCoreKit.podspec \
      --skip-import-validation \
      --verbose

You will also need to have [SignalCoreKit][] checked out; the above command assumes you have checked it out as a sibling directory to libsignal-client.

[SignalCoreKit]: https://github.com/signalapp/SignalCoreKit


# Development as a Swift Package

1. Build the Rust library using `swift/build_ffi.sh -d`. (The Package.swift is configured to use the debug build of the Rust libraries, since they are likely being developed in tandom.)

2. Use `swift build` and `swift test` as usual from within the `swift/` directory.


## Use as a Swift Package

...is not supported. In theory we could make this work through the use of a custom pkg-config file and requiring clients to set `PKG_CONFIG_PATH` (or install the Rust build products), but since Signal itself does not use this configuration it's considered extra maintenance burden. Development as a package is supported as a lightweight convenience (as well as a cross-platform one), but the CocoaPods build is considered the canonical one.
