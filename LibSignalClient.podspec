#
# Copyright 2020-2022 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

Pod::Spec.new do |s|
  s.name             = 'LibSignalClient'
  s.version          = '0.21.1'
  s.summary          = 'A Swift wrapper library for communicating with the Signal messaging service.'

  s.homepage         = 'https://github.com/signalapp/libsignal'
  s.license          = 'AGPL-3.0-only'
  s.author           = 'Signal Messenger LLC'
  s.source           = { :git => 'https://github.com/signalapp/libsignal.git', :tag => "v#{s.version}" }

  s.swift_version    = '5'
  # We use this to set IPHONEOS_DEPLOYMENT_TARGET below.
  # The Rust compiler driver expects this to always be in the form 'major.minor'.
  min_deployment_target = '12.2'
  s.platform         = :ios, min_deployment_target

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

      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=arm64]' => 'aarch64-apple-ios-sim',
      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=*]' => 'x86_64-apple-ios',
      'CARGO_BUILD_TARGET[sdk=iphoneos*]' => 'aarch64-apple-ios',
      # Presently, there's no special SDK or arch for maccatalyst,
      # so we need to hackily use the "IS_MACCATALYST" build flag
      # to set the appropriate cargo target
      'CARGO_BUILD_TARGET_MAC_CATALYST_ARM_' => 'aarch64-apple-darwin',
      'CARGO_BUILD_TARGET_MAC_CATALYST_ARM_YES' => 'aarch64-apple-ios-macabi',
      'CARGO_BUILD_TARGET[sdk=macosx*][arch=arm64]' => '$(CARGO_BUILD_TARGET_MAC_CATALYST_ARM_$(IS_MACCATALYST))',
      'CARGO_BUILD_TARGET_MAC_CATALYST_X86_' => 'x86_64-apple-darwin',
      'CARGO_BUILD_TARGET_MAC_CATALYST_X86_YES' => 'x86_64-apple-ios-macabi',
      'CARGO_BUILD_TARGET[sdk=macosx*][arch=*]' => '$(CARGO_BUILD_TARGET_MAC_CATALYST_X86_$(IS_MACCATALYST))',

      'ARCHS[sdk=iphonesimulator*]' => 'x86_64 arm64',
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

  s.prepare_command = %Q(
    set -euo pipefail
    export IPHONEOS_DEPLOYMENT_TARGET=#{min_deployment_target}
    CARGO_BUILD_TARGET=aarch64-apple-ios swift/build_ffi.sh --release
    CARGO_BUILD_TARGET=x86_64-apple-ios swift/build_ffi.sh --release
    CARGO_BUILD_TARGET=aarch64-apple-ios-sim swift/build_ffi.sh --release
    if [[ "${SKIP_CATALYST:-0}" != "1" ]]; then
      CARGO_BUILD_TARGET=x86_64-apple-ios-macabi swift/build_ffi.sh --release --build-std
      CARGO_BUILD_TARGET=aarch64-apple-ios-macabi swift/build_ffi.sh --release --build-std
    fi
  )

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'swift/Tests/*/*.swift'
    test_spec.pod_target_xcconfig = {
      'LIBSIGNAL_FFI_LIB_IF_NEEDED' => '',
    }
  end
end
