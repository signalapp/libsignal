//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(warnings)]

use libsignal_protocol_rust::*;

#[cfg(feature = "ffi")]
#[macro_use]
mod support_ffi;
#[cfg(feature = "ffi")]
pub use support_ffi::*;

#[cfg(feature = "jni")]
#[macro_use]
mod support_jni;
#[cfg(feature = "jni")]
pub use support_jni::*;

bridge_destroy!(
    ProtocolAddress,
    ffi = address_destroy,
    jni = ProtocolAddress_1Destroy
);
