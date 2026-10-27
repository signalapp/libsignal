//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi

// Called from checkError, which every app that uses libsignal links, so dead stripping can't remove
// this reference. A mismatched libsignal_ffi causes linking to fail.
//
// To check that a release build still references the version symbol, run from the repo root:
//
//     swift build -c release --target LibSignalClient
//     nm .build/release/LibSignalClient.build/Error.swift.o | grep signal_ffi_version
//
// The output should include an undefined symbol, "U _signal_ffi_version_X_Y_Z". In release builds
// this function gets inlined into checkError, so the reference shows up in Error.swift.o, not
// FfiVersion.swift.o.
internal func checkFfiVersion() {
    signal_ffi_version_0_106_1()
}
