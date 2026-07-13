//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() {
    // Set environment variables for bridge_fn to produce correctly-named symbols for FFI and JNI.
    println!("cargo:rustc-env=LIBSIGNAL_BRIDGE_FN_PREFIX_FFI=signal_");
}
