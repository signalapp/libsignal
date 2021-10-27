//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::panic::RefUnwindSafe;

use ::hsm_enclave;
use libsignal_bridge_macros::*;

use crate::support::*;
use crate::*;
use hsm_enclave::Result;

pub enum HsmEnclaveClient {
    ConnectionEstablishment(hsm_enclave::ClientConnectionEstablishment),
    Connection(hsm_enclave::ClientConnection),
    InvalidConnectionState,
}

impl RefUnwindSafe for HsmEnclaveClient {}

impl HsmEnclaveClient {
    pub fn new(trusted_public_key: &[u8], trusted_code_hashes: &[u8]) -> Result<Self> {
        if trusted_public_key.len() != hsm_enclave::PUB_KEY_SIZE {
            return Err(hsm_enclave::Error::InvalidPublicKeyError);
        }
        if trusted_code_hashes.is_empty()
            || trusted_code_hashes.len() % hsm_enclave::CODE_HASH_SIZE != 0
        {
            return Err(hsm_enclave::Error::InvalidCodeHashError);
        }
        let mut pubkey = [0u8; hsm_enclave::PUB_KEY_SIZE];
        pubkey.copy_from_slice(trusted_public_key);
        let mut hashes: Vec<[u8; hsm_enclave::CODE_HASH_SIZE]> = Vec::new();
        for code_hash in trusted_code_hashes.chunks(hsm_enclave::CODE_HASH_SIZE) {
            let mut hash = [0u8; hsm_enclave::CODE_HASH_SIZE];
            hash.copy_from_slice(code_hash);
            hashes.push(hash);
        }
        Ok(HsmEnclaveClient::ConnectionEstablishment(
            hsm_enclave::ClientConnectionEstablishment::new(pubkey, hashes)?,
        ))
    }

    pub fn initial_request(&self) -> Result<&[u8]> {
        match self {
            HsmEnclaveClient::ConnectionEstablishment(c) => Ok(c.initial_request()),
            _ => Err(hsm_enclave::Error::InvalidBridgeStateError),
        }
    }

    pub fn complete_handshake(&mut self, handshake_received: &[u8]) -> Result<()> {
        match std::mem::replace(self, HsmEnclaveClient::InvalidConnectionState) {
            HsmEnclaveClient::ConnectionEstablishment(c) => {
                *self = HsmEnclaveClient::Connection(c.complete(handshake_received)?);
                Ok(())
            }
            _ => Err(hsm_enclave::Error::InvalidBridgeStateError),
        }
    }

    pub fn established_send(&mut self, plaintext_to_send: &[u8]) -> Result<Vec<u8>> {
        match self {
            HsmEnclaveClient::Connection(c) => c.send(plaintext_to_send),
            _ => Err(hsm_enclave::Error::InvalidBridgeStateError),
        }
    }

    pub fn established_recv(&mut self, received_ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            HsmEnclaveClient::Connection(c) => c.recv(received_ciphertext),
            _ => Err(hsm_enclave::Error::InvalidBridgeStateError),
        }
    }
}

bridge_handle!(HsmEnclaveClient, clone = false, mut = true);

#[bridge_fn]
fn HsmEnclaveClient_New(
    trusted_public_key: &[u8],
    trusted_code_hashes: &[u8],
) -> Result<HsmEnclaveClient> {
    HsmEnclaveClient::new(trusted_public_key, trusted_code_hashes)
}

bridge_get_buffer!(
    HsmEnclaveClient::initial_request as InitialRequest -> &[u8]
);

#[bridge_fn_void]
fn HsmEnclaveClient_CompleteHandshake(
    cli: &mut HsmEnclaveClient,
    handshake_received: &[u8],
) -> Result<()> {
    cli.complete_handshake(handshake_received)
}

#[bridge_fn_buffer]
fn HsmEnclaveClient_EstablishedSend(
    cli: &mut HsmEnclaveClient,
    plaintext_to_send: &[u8],
) -> Result<Vec<u8>> {
    cli.established_send(plaintext_to_send)
}

#[bridge_fn_buffer]
fn HsmEnclaveClient_EstablishedRecv(
    cli: &mut HsmEnclaveClient,
    received_ciphertext: &[u8],
) -> Result<Vec<u8>> {
    cli.established_recv(received_ciphertext)
}
