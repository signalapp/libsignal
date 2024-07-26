//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::panic::RefUnwindSafe;

use ::attest::enclave::Result;
use ::attest::{client_connection, enclave};

use crate::*;

// It's okay to have a large enum because this type will be boxed for bridging after it's been
// created.
#[allow(clippy::large_enum_variant)]
pub enum SgxClientState {
    ConnectionEstablishment(enclave::Handshake),
    Connection(client_connection::ClientConnection),
    InvalidConnectionState,
}

impl RefUnwindSafe for SgxClientState {}

impl SgxClientState {
    pub fn new(handshake: enclave::Handshake) -> Result<Self> {
        Ok(SgxClientState::ConnectionEstablishment(handshake))
    }

    pub fn initial_request(&self) -> Result<&[u8]> {
        match self {
            SgxClientState::ConnectionEstablishment(c) => Ok(c.initial_request()),
            _ => Err(enclave::Error::InvalidBridgeStateError),
        }
    }

    pub fn complete_handshake(&mut self, initial_received: &[u8]) -> Result<()> {
        match std::mem::replace(self, SgxClientState::InvalidConnectionState) {
            SgxClientState::ConnectionEstablishment(c) => {
                *self = SgxClientState::Connection(c.complete(initial_received)?);
                Ok(())
            }
            _ => Err(enclave::Error::InvalidBridgeStateError),
        }
    }

    pub fn established_send(&mut self, plaintext_to_send: &[u8]) -> Result<Vec<u8>> {
        match self {
            SgxClientState::Connection(c) => match c.send(plaintext_to_send) {
                Ok(v) => Ok(v),
                Err(e) => Err(enclave::Error::NoiseError(e)),
            },
            _ => Err(enclave::Error::InvalidBridgeStateError),
        }
    }

    pub fn established_recv(&mut self, received_ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            SgxClientState::Connection(c) => match c.recv(received_ciphertext) {
                Ok(v) => Ok(v),
                Err(e) => Err(enclave::Error::NoiseError(e)),
            },
            _ => Err(enclave::Error::InvalidBridgeStateError),
        }
    }
}

bridge_as_handle!(SgxClientState, mut = true);
