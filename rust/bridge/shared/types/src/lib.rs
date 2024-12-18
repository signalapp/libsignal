//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]

#[cfg(feature = "ffi")]
#[macro_use]
pub mod ffi;

#[cfg(feature = "jni")]
#[macro_use]
pub mod jni;

#[cfg(feature = "node")]
#[macro_use]
pub mod node;

#[macro_use]
pub mod support;

pub use support::{describe_panic, AsyncRuntime, ResultReporter};

pub mod cds2;
pub mod crypto;
pub mod hsm_enclave;
pub mod net;
pub mod protocol;
pub mod sgx_session;
pub mod zkgroup;

// Desktop does not use SVR
#[cfg(any(feature = "jni", feature = "ffi"))]
mod pin {
    use ::libsignal_account_keys::PinHash;

    use crate::*;

    bridge_as_handle!(PinHash, node = false);
}

pub mod incremental_mac;
pub mod message_backup;

pub mod io;
pub mod keytrans;

pub mod media {
    // Wrapper struct for cbindgen
    #[derive(Clone, Debug)]
    pub struct SanitizedMetadata(
        // This `cfg` should really go on the type instead of its members since
        // the only code that uses the type is similarly conditionally enabled.
        // The problem is that cbindgen generates a typedef that references this
        // type even when the feature is disabled. Having the type always
        // present works around this bug.
        #[cfg(feature = "signal-media")] pub signal_media::sanitize::mp4::SanitizedMetadata,
    );

    use crate::*;

    bridge_as_handle!(SanitizedMetadata);
}
