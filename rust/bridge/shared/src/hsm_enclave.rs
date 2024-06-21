//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::attest::hsm_enclave;
use libsignal_bridge_macros::*;
use libsignal_bridge_types::hsm_enclave::HsmEnclaveClient;

use self::hsm_enclave::Result;
use crate::support::*;
use crate::*;

bridge_handle_fns!(HsmEnclaveClient, clone = false);

#[bridge_fn]
fn HsmEnclaveClient_New(
    trusted_public_key: &[u8],
    trusted_code_hashes: &[u8],
) -> Result<HsmEnclaveClient> {
    HsmEnclaveClient::new(trusted_public_key, trusted_code_hashes)
}

#[bridge_fn]
fn HsmEnclaveClient_CompleteHandshake(
    cli: &mut HsmEnclaveClient,
    handshake_received: &[u8],
) -> Result<()> {
    cli.complete_handshake(handshake_received)
}

#[bridge_fn]
fn HsmEnclaveClient_EstablishedSend(
    cli: &mut HsmEnclaveClient,
    plaintext_to_send: &[u8],
) -> Result<Vec<u8>> {
    cli.established_send(plaintext_to_send)
}

#[bridge_fn]
fn HsmEnclaveClient_EstablishedRecv(
    cli: &mut HsmEnclaveClient,
    received_ciphertext: &[u8],
) -> Result<Vec<u8>> {
    cli.established_recv(received_ciphertext)
}

bridge_get!(
    HsmEnclaveClient::initial_request as InitialRequest -> &[u8]
);
