#
# Copyright 2020-2022 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

Pod::Spec.new do |s|
  s.name             = 'LibSignalClient'
  s.version          = '0.30.1'
  s.summary          = 'A Swift wrapper library for communicating with the Signal messaging service.'

  s.homepage         = 'https://github.com/signalapp/libsignal'
  s.license          = 'AGPL-3.0-only'
  s.author           = 'Signal Messenger LLC'
  s.source           = { :git => 'https://github.com/signalapp/libsignal.git', :tag => "v#{s.version}" }

  s.swift_version    = '5'
  s.platform         = :ios, '13.0'

  s.dependency 'SignalCoreKit'

  s.source_files = ['swift/Sources/**/*.swift', 'swift/Sources/**/*.m']
  s.preserve_paths = [
    'swift/Sources/SignalFfi',
    'bin/fetch_archive.py',
  ]

  s.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/swift/Sources/SignalFfi',
      # Duplicate this here to make sure the search path is passed on to Swift dependencies.
      'SWIFT_INCLUDE_PATHS' => '$(HEADER_SEARCH_PATHS)',

      'LIBSIGNAL_FFI_BUILD_PATH' => 'target/$(CARGO_BUILD_TARGET)/release',
      # Store libsignal_ffi.a builds in a project-wide directory
      # because we keep simulator and device builds next to each other.
      'LIBSIGNAL_FFI_TEMP_DIR' => '$(PROJECT_TEMP_DIR)/libsignal_ffi',
      'LIBSIGNAL_FFI_LIB_TO_LINK' => '$(LIBSIGNAL_FFI_TEMP_DIR)/$(LIBSIGNAL_FFI_BUILD_PATH)/libsignal_ffi.a',

      # Make sure we link the static library, not a dynamic one.
      'OTHER_LDFLAGS' => '$(LIBSIGNAL_FFI_LIB_TO_LINK)',

      'LIBSIGNAL_FFI_PREBUILD_ARCHIVE' => "libsignal-client-ios-build-v#{s.version}.tar.gz",
      'LIBSIGNAL_FFI_PREBUILD_CHECKSUM' => ENV.fetch('LIBSIGNAL_FFI_PREBUILD_CHECKSUM', ''),

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
    { name: 'Download and cache libsignal-ffi',
      execution_position: :before_compile,
      script: %q(
        set -euo pipefail
        if [ -e "${PODS_TARGET_SRCROOT}/swift/build_ffi.sh" ]; then
          # Local development
          exit 0
        fi
        "${PODS_TARGET_SRCROOT}"/bin/fetch_archive.py -u "https://build-artifacts.signal.org/libraries/${LIBSIGNAL_FFI_PREBUILD_ARCHIVE}" -c "${LIBSIGNAL_FFI_PREBUILD_CHECKSUM}" -o "${USER_LIBRARY_DIR}/Caches/org.signal.libsignal"
      ),
    },
    { name: 'Extract libsignal-ffi prebuild',
      execution_position: :before_compile,
      input_files: ['$(USER_LIBRARY_DIR)/Caches/org.signal.libsignal/$(LIBSIGNAL_FFI_PREBUILD_ARCHIVE)'],
      output_files: ['$(LIBSIGNAL_FFI_LIB_TO_LINK)'],
      script: %q(
        set -euo pipefail
        rm -rf "${LIBSIGNAL_FFI_TEMP_DIR}"
        if [ -e "${PODS_TARGET_SRCROOT}/swift/build_ffi.sh" ]; then
          # Local development
          ln -fhs "${PODS_TARGET_SRCROOT}" "${LIBSIGNAL_FFI_TEMP_DIR}"
        elif [ -e "${SCRIPT_INPUT_FILE_0}" ]; then
          mkdir -p "${LIBSIGNAL_FFI_TEMP_DIR}"
          cd "${LIBSIGNAL_FFI_TEMP_DIR}"
          tar --modification-time -x -f "${SCRIPT_INPUT_FILE_0}"
        else
          echo 'error: could not download libsignal_ffi.a; please provide LIBSIGNAL_FFI_PREBUILD_CHECKSUM' >&2
          exit 1
        fi
      ),
    }
  ]

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'swift/Tests/*/*.swift'
    test_spec.preserve_paths = [
      'swift/Tests/*/Resources',
    ]
    test_spec.pod_target_xcconfig = {
      # Don't also link into the test target.
      'LIBSIGNAL_FFI_LIB_TO_LINK' => '',
    }
  end
end
