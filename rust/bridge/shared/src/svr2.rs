//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::attest::sgx_session::Result;
use ::attest::svr2;
use libsignal_bridge_macros::*;

use crate::protocol::Timestamp;
use crate::sgx_session::SgxClientState;
use crate::support::*;
use crate::*;

bridge_handle!(Svr2Client, clone = false, mut = true, node = false);

#[cfg(any(feature = "jni", feature = "ffi"))]
pub struct Svr2Client {
    client_state: SgxClientState,
    group_id: u64,
}

#[bridge_fn(node = false)]
fn Svr2Client_TakeSgxClientState(svr2_client: &mut Svr2Client) -> SgxClientState {
    std::mem::replace(
        &mut svr2_client.client_state,
        SgxClientState::InvalidConnectionState,
    )
}

#[bridge_fn(node = false)]
fn Svr2Client_GroupId(svr2_client: &Svr2Client) -> u64 {
    svr2_client.group_id
}

/// Builds an SGX client for the svr2 service and extracts the groupID
#[cfg(any(feature = "jni", feature = "ffi"))]
fn new_client(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
) -> Result<Svr2Client> {
    let handshake = svr2::new_handshake(mrenclave, attestation_msg, current_time)?;
    Ok(Svr2Client {
        client_state: SgxClientState::new(handshake.handshake)?,
        group_id: handshake.group_id,
    })
}

#[bridge_fn(node = false)]
fn Svr2Client_New(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_timestamp: Timestamp,
) -> Result<Svr2Client> {
    new_client(
        mrenclave,
        attestation_msg,
        std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_millis(current_timestamp.as_millis()),
    )
}
