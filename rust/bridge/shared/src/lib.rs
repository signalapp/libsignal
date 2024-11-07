//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]

#[cfg(not(any(feature = "ffi", feature = "jni", feature = "node")))]
compile_error!("Feature \"ffi\", \"jni\", or \"node\" must be enabled for this crate.");

pub use libsignal_bridge_types::{
    bridge_as_handle, bridge_deserialize, bridge_fixed_length_serializable_fns, bridge_get,
    bridge_handle_fns, bridge_serializable_handle_fns, describe_panic, io, support,
};
#[cfg(feature = "ffi")]
pub use libsignal_bridge_types::{ffi, ffi_arg_type, ffi_result_type};
#[cfg(feature = "jni")]
pub use libsignal_bridge_types::{
    jni, jni_arg_type, jni_args, jni_class_name, jni_result_type, jni_signature,
};
#[cfg(feature = "node")]
pub use libsignal_bridge_types::{node, node_register};

pub mod logging;

pub mod crypto;
pub mod protocol;

// Desktop does not make use of device transfer certificates
#[cfg(any(feature = "jni", feature = "ffi"))]
pub mod device_transfer;

mod cds2;
mod hsm_enclave;
mod sgx_session;

pub mod zkgroup;

pub mod net;

mod account_keys;

// Desktop does not use SVR
#[cfg(any(feature = "jni", feature = "ffi"))]
mod svr2;

pub mod incremental_mac;
pub mod message_backup;
pub mod usernames;

#[cfg(feature = "signal-media")]
pub mod media;
