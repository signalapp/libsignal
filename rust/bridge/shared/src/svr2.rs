//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::attest::sgx_session::Result;
use ::attest::svr2;
use libsignal_bridge_macros::*;

use crate::protocol::Timestamp;
use crate::sgx_session::SgxClientState;
#[allow(unused_imports)]
use crate::support::*;
use crate::*;

/// Builds an SGX client for the svr2 service
#[cfg(any(feature = "jni", feature = "ffi"))]
fn new_client(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
) -> Result<SgxClientState> {
    SgxClientState::new(svr2::new_handshake(
        mrenclave,
        attestation_msg,
        current_time,
    )?)
}

#[bridge_fn(node = false)]
fn Svr2Client_New(
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
