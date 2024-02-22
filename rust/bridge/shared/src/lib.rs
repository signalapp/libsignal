//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]

#[cfg(not(any(feature = "ffi", feature = "jni", feature = "node")))]
compile_error!("Feature \"ffi\", \"jni\", or \"node\" must be enabled for this crate.");

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
mod support;

pub mod logging;

pub use support::{describe_panic, AsyncRuntime, ResultReporter};

pub mod crypto;
pub mod protocol;

// Desktop does not make use of device transfer certificates
#[cfg(any(feature = "jni", feature = "ffi"))]
pub mod device_transfer;

mod cds2;
mod sgx_session;

mod hsm_enclave;

pub mod zkgroup;

#[cfg(feature = "ffi")]
pub mod ias;

pub mod net;

// Desktop does not use SVR
#[cfg(any(feature = "jni", feature = "ffi"))]
mod pin;
#[cfg(any(feature = "jni", feature = "ffi"))]
mod svr2;

pub mod incremental_mac;
pub mod message_backup;
pub mod usernames;

mod io;

#[cfg(feature = "signal-media")]
pub mod media;

// These APIs are only useful for tests. To save on code size, we omit them by default.
// To run tests, build with `--features testing-fns`.
#[cfg(feature = "testing-fns")]
mod testing;
