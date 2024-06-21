//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::attest::enclave::Result;
use libsignal_bridge_macros::*;
use libsignal_bridge_types::sgx_session::SgxClientState;

use crate::support::*;
use crate::*;

bridge_handle_fns!(SgxClientState, clone = false);

bridge_get!(
    SgxClientState::initial_request as InitialRequest -> &[u8]
);

#[bridge_fn]
fn SgxClientState_CompleteHandshake(
    cli: &mut SgxClientState,
    handshake_received: &[u8],
) -> Result<()> {
    cli.complete_handshake(handshake_received)
}

#[bridge_fn]
fn SgxClientState_EstablishedSend(
    cli: &mut SgxClientState,
    plaintext_to_send: &[u8],
) -> Result<Vec<u8>> {
    cli.established_send(plaintext_to_send)
}

#[bridge_fn]
fn SgxClientState_EstablishedRecv(
    cli: &mut SgxClientState,
    received_ciphertext: &[u8],
) -> Result<Vec<u8>> {
    cli.established_recv(received_ciphertext)
}
