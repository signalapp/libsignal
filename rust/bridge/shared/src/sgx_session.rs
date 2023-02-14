//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::panic::RefUnwindSafe;

use ::attest::{client_connection, sgx_session};
use libsignal_bridge_macros::*;

use crate::support::*;
use crate::*;
use ::attest::sgx_session::Result;

// It's okay to have a large enum because this type will be boxed for bridging after it's been
// created.
#[allow(clippy::large_enum_variant)]
pub enum SgxClientState {
    ConnectionEstablishment(sgx_session::Handshake),
    Connection(client_connection::ClientConnection),
    InvalidConnectionState,
}

impl RefUnwindSafe for SgxClientState {}

impl SgxClientState {
    pub fn new(handshake: sgx_session::Handshake) -> Result<Self> {
        Ok(SgxClientState::ConnectionEstablishment(handshake))
    }

    pub fn initial_request(&self) -> Result<&[u8]> {
        match self {
            SgxClientState::ConnectionEstablishment(c) => Ok(c.initial_request()),
            _ => Err(sgx_session::Error::InvalidBridgeStateError),
        }
    }

    pub fn complete_handshake(&mut self, initial_received: &[u8]) -> Result<()> {
        match std::mem::replace(self, SgxClientState::InvalidConnectionState) {
            SgxClientState::ConnectionEstablishment(c) => {
                *self = SgxClientState::Connection(c.complete(initial_received)?);
                Ok(())
            }
            _ => Err(sgx_session::Error::InvalidBridgeStateError),
        }
    }

    pub fn established_send(&mut self, plaintext_to_send: &[u8]) -> Result<Vec<u8>> {
        match self {
            SgxClientState::Connection(c) => match c.send(plaintext_to_send) {
                Ok(v) => Ok(v),
                Err(e) => Err(sgx_session::Error::NoiseError(e)),
            },
            _ => Err(sgx_session::Error::InvalidBridgeStateError),
        }
    }

    pub fn established_recv(&mut self, received_ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            SgxClientState::Connection(c) => match c.recv(received_ciphertext) {
                Ok(v) => Ok(v),
                Err(e) => Err(sgx_session::Error::NoiseError(e)),
            },
            _ => Err(sgx_session::Error::InvalidBridgeStateError),
        }
    }
}

bridge_handle!(SgxClientState, clone = false, mut = true);

bridge_get!(
    SgxClientState::initial_request as InitialRequest -> &[u8]
);

#[bridge_fn_void]
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
