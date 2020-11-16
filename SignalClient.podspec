#
# Copyright 2020 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

Pod::Spec.new do |s|
  s.name             = 'SignalClient'
  s.version          = '0.1.0'
  s.summary          = 'A Swift wrapper library for communicating with the Signal messaging service.'

  s.homepage         = 'https://github.com/signalapp/libsignal-client'
  s.license          = 'AGPL-3.0-only'
  s.author           = { 'Jack Lloyd' => 'jack@signal.org', 'Jordan Rose' => 'jrose@signal.org' }
  s.source           = { :git => 'https://github.com/signalapp/libsignal-client.git', :tag => "v#{s.version}" }

  s.swift_version    = '5'
  s.ios.deployment_target  = '8'
  s.osx.deployment_target  = '10.9'

  s.source_files = 'swift/Sources/**/*.swift'
  s.preserve_paths = [
    'bin/*',
    'Cargo.toml',
    'Cargo.lock',
    'rust-toolchain',
    'rust/*',
    'swift/*.sh',
    'swift/Sources/SignalFfi',
  ]

  s.pod_target_xcconfig = {
      'CARGO_BUILD_TARGET_DIR' => '$(DERIVED_FILE_DIR)/libsignal-ffi',
      'LIBSIGNAL_FFI_DIR' => '$(CARGO_BUILD_TARGET_DIR)/$(CARGO_BUILD_TARGET)/release',

      'SWIFT_INCLUDE_PATHS' => '$(PODS_TARGET_SRCROOT)/swift/Sources/SignalFfi $(LIBSIGNAL_FFI_DIR)',

      # Make sure we link the static library, not a dynamic one.
      # Use an extra level of indirection because CocoaPods messes with OTHER_LDFLAGS too.
      'LIBSIGNAL_FFI_LIB_IF_NEEDED' => '$(LIBSIGNAL_FFI_DIR)/libsignal_ffi.a',
      'OTHER_LDFLAGS' => '$(LIBSIGNAL_FFI_LIB_IF_NEEDED)',

      # Some day this will have to be updated for arm64 Macs (and the corresponding arm64 iOS simulator)
      'CARGO_BUILD_TARGET[sdk=iphonesimulator*]' => 'x86_64-apple-ios',
      'CARGO_BUILD_TARGET[sdk=iphoneos*]' => 'aarch64-apple-ios',
      'CARGO_BUILD_TARGET[sdk=macosx*]' => 'x86_64-apple-darwin',
      'ARCHS[sdk=iphonesimulator*]' => 'x86_64',
      'ARCHS[sdk=iphoneos*]' => 'arm64',
  }

  s.script_phases = [
    { :name => 'Build libsignal-ffi',
      :execution_position => :before_compile,
      :script => '"${PODS_TARGET_SRCROOT}/swift/build_ffi.sh"',
    }
  ]

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'swift/Tests/*/*.swift'
    test_spec.pod_target_xcconfig = {
      'LIBSIGNAL_FFI_LIB_IF_NEEDED' => '',
    }
  end
end
