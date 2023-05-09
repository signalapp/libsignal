//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(all(not(target_os = "android"), feature = "jni"))]
use std::collections::HashMap;

use ::attest::cds2;
use ::attest::sgx_session::Result;
use libsignal_bridge_macros::*;

use crate::protocol::Timestamp;
use crate::sgx_session::SgxClientState;
#[allow(unused_imports)]
use crate::support::*;
use crate::*;

/// Builds an SGX client for the cds2 service
fn new_client(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
) -> Result<SgxClientState> {
    SgxClientState::new(cds2::new_handshake(
        mrenclave,
        attestation_msg,
        current_time,
    )?)
}

#[bridge_fn]
fn Cds2ClientState_New(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_timestamp: Timestamp,
) -> Result<SgxClientState> {
    new_client(
        mrenclave,
        attestation_msg,
        std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_millis(current_timestamp.as_millis()),
    )
}

#[cfg(all(not(target_os = "android"), feature = "jni"))]
pub struct Cds2Metrics(pub HashMap<String, i64>);

#[cfg(not(target_os = "android"))]
#[bridge_fn(ffi = false, node = false)]
fn Cds2Metrics_extract(attestation_msg: &[u8]) -> Result<Cds2Metrics> {
    cds2::extract_metrics(attestation_msg).map(Cds2Metrics)
}
