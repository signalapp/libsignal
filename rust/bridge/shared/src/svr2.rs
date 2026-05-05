//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::attest::enclave::Result;
use ::attest::svr2;
use libsignal_bridge_macros::*;
use libsignal_bridge_types::sgx_session::SgxClientState;

use crate::protocol::Timestamp;
#[allow(unused_imports)]
use crate::support::*;
use crate::*;

#[bridge_fn]
fn Svr2Client_New(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_timestamp: Timestamp,
) -> Result<SgxClientState> {
    SgxClientState::new(svr2::new_handshake_with_raft_config_lookup(
        mrenclave,
        attestation_msg,
        current_timestamp.into(),
    )?)
}
