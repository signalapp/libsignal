//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Import bridged functions. Without this, the compiler and/or linker are too
// smart and don't include the symbols in the library.
#[allow(unused_imports)]
use libsignal_bridge_testing::*;
#[allow(unused_imports)]
use libsignal_jni_impl::*;
