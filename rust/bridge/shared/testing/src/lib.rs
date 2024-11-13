//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(not(any(feature = "ffi", feature = "jni", feature = "node")))]
compile_error!("Feature \"ffi\", \"jni\", or \"node\" must be enabled for this crate.");

use libsignal_bridge_macros::bridge_fn;
#[cfg(feature = "node")]
pub use libsignal_bridge_types::node;
use libsignal_bridge_types::support::*;
use libsignal_bridge_types::*;

#[bridge_fn]
pub fn test_only_fn_returns_123() -> u32 {
    123
}

pub mod convert;
mod keytrans;
pub mod message_backup;
pub mod net;
#[cfg(feature = "node")]
pub mod net_env;
pub mod types;
