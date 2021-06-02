#
# Copyright 2020-2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

Pod::Spec.new do |s|
  s.name             = 'SignalClient'
  s.version          = '0.8.1'
  s.summary          = 'A Swift wrapper library for communicating with the Signal messaging service.'

  s.homepage         = 'https://github.com/signalapp/libsignal-client'
  s.license          = 'AGPL-3.0-only'
  s.author           = { 'Jack Lloyd' => 'jack@signal.org', 'Jordan Rose' => 'jrose@signal.org' }
  s.source           = { :git => 'https://github.com/signalapp/libsignal-client.git', :tag => "swift-#{s.version}" }

  s.swift_version    = '5'
  s.platform = :ios, '10'

  s.dependency 'SignalCoreKit'

  s.source_files = ['swift/Sources/**/*.swift', 'swift/Sources/**/*.m']
  s.preserve_paths = [
    'target/*/release/libsignal_ffi.a',
    'swift/Sources/SignalFfi',
  ]

  s.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/swift/Sources/SignalFfi',
      # Duplicate this here to make sure the search path is passed on to Swift dependencies.
      'SWIFT_INCLUDE_PATHS' => '$(HEADER_SEARCH_PATHS)',

      # Make sure we link the static library, not a dynamic one.
      # Use an extra level of indirection because CocoaPods messes with OTHER_LDFLAGS too.
      'LIBSIGNAL_FFI_LIB_IF_NEEDED' => '$(PODS_TARGET_SRCROOT)/target/$(CARGO_BUILD_TARGET)/release/libsignal_ffi.a',
      'OTHER_LDFLAGS' => '$(LIBSIGNAL_FFI_LIB_IF_NEEDED)',

      # Some day this will have to be updated for arm64 Macs (and the corresponding arm64 iOS simulator)
      'CARGO_BUILD_TARGET[sdk=iphonesimulator*]' => 'x86_64-apple-ios',
      'CARGO_BUILD_TARGET[sdk=iphoneos*]' => 'aarch64-apple-ios',
      'CARGO_BUILD_TARGET[sdk=macosx*]' => 'x86_64-apple-darwin',
      'ARCHS[sdk=iphonesimulator*]' => 'x86_64',
      'ARCHS[sdk=iphoneos*]' => 'arm64',
  }

  s.script_phases = [
    { :name => 'Check libsignal-ffi',
      :execution_position => :before_compile,
      :script => %q(
        test -e "${LIBSIGNAL_FFI_LIB_IF_NEEDED}" && exit 0
        if test -e "${PODS_TARGET_SRCROOT}/swift/build_ffi.sh"; then
          echo 'error: libsignal_ffi.a not built; run the following to build it:' >&2
          echo "CARGO_BUILD_TARGET=${CARGO_BUILD_TARGET} \"${PODS_TARGET_SRCROOT}/swift/build_ffi.sh\" --release" >&2
        else
          echo 'error: libsignal_ffi.a not built; try re-running `pod install`' >&2
        fi
        false
      ),
    }
  ]

  s.prepare_command = %q(
    set -euo pipefail
    CARGO_BUILD_TARGET=aarch64-apple-ios swift/build_ffi.sh --release
    CARGO_BUILD_TARGET=x86_64-apple-ios swift/build_ffi.sh --release
  )

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'swift/Tests/*/*.swift'
    test_spec.pod_target_xcconfig = {
      'LIBSIGNAL_FFI_LIB_IF_NEEDED' => '',
    }
  end
end
