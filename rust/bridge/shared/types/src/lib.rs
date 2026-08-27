//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]

#[cfg(feature = "metadata")]
pub mod metadata;

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

pub use support::{AsyncRuntime, ResultReporter, describe_panic};

pub mod cds2;
pub mod crypto;
pub mod hsm_enclave;
pub mod net;
pub mod protocol;
pub mod sgx_session;
pub mod zkgroup;

mod pin {
    use ::libsignal_account_keys::PinHash;

    use crate::*;

    bridge_as_handle!(PinHash);
}

pub mod incremental_mac;
pub mod message_backup;

pub mod io;

#[cfg(feature = "signal-media")]
pub mod media {
    use signal_media::sanitize::mp4::SanitizedMetadata;

    use crate::*;

    bridge_as_handle!(SanitizedMetadata);
}
