//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi

// Called from setUpLibsignalLogging(level:), which every app that uses libsignal uses, so dead
// stripping won't remove this reference. A mismatched libsignal_ffi causes linking to fail.
internal func checkFfiVersion() {
    signal_ffi_version_0_106_2()
}
