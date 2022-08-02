//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(all(not(target_os = "android"), feature = "jni"))]
use std::collections::HashMap;
use std::panic::RefUnwindSafe;

use ::attest::cds2;
use libsignal_bridge_macros::*;

use crate::protocol::Timestamp;
use crate::support::*;
use crate::*;
use ::attest::cds2::Result;
use ::attest::client_connection;

// It's okay to have a large enum because this type will be boxed for bridging after it's been
// created.
#[allow(clippy::large_enum_variant)]
pub enum Cds2ClientState {
    ConnectionEstablishment(cds2::ClientConnectionEstablishment),
    Connection(client_connection::ClientConnection),
    InvalidConnectionState,
}

impl RefUnwindSafe for Cds2ClientState {}

impl Cds2ClientState {
    pub fn new(
        mrenclave: &[u8],
        attestation_msg: &[u8],
        current_time: std::time::SystemTime,
    ) -> Result<Self> {
        Ok(Cds2ClientState::ConnectionEstablishment(
            cds2::ClientConnectionEstablishment::new(mrenclave, attestation_msg, current_time)?,
        ))
    }

    pub fn initial_request(&self) -> Result<&[u8]> {
        match self {
            Cds2ClientState::ConnectionEstablishment(c) => Ok(c.initial_request()),
            _ => Err(cds2::Error::InvalidBridgeStateError),
        }
    }

    pub fn complete_handshake(&mut self, initial_received: &[u8]) -> Result<()> {
        match std::mem::replace(self, Cds2ClientState::InvalidConnectionState) {
            Cds2ClientState::ConnectionEstablishment(c) => {
                *self = Cds2ClientState::Connection(c.complete(initial_received)?);
                Ok(())
            }
            _ => Err(cds2::Error::InvalidBridgeStateError),
        }
    }

    pub fn established_send(&mut self, plaintext_to_send: &[u8]) -> Result<Vec<u8>> {
        match self {
            Cds2ClientState::Connection(c) => match c.send(plaintext_to_send) {
                Ok(v) => Ok(v),
                Err(e) => Err(cds2::Error::NoiseError(e)),
            },
            _ => Err(cds2::Error::InvalidBridgeStateError),
        }
    }

    pub fn established_recv(&mut self, received_ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Cds2ClientState::Connection(c) => match c.recv(received_ciphertext) {
                Ok(v) => Ok(v),
                Err(e) => Err(cds2::Error::NoiseError(e)),
            },
            _ => Err(cds2::Error::InvalidBridgeStateError),
        }
    }
}

bridge_handle!(Cds2ClientState, clone = false, mut = true);
#[bridge_fn]
fn Cds2ClientState_New(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_timestamp: Timestamp,
) -> Result<Cds2ClientState> {
    Cds2ClientState::new(
        mrenclave,
        attestation_msg,
        std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_millis(current_timestamp.as_millis()),
    )
}

bridge_get_buffer!(
    Cds2ClientState::initial_request as InitialRequest -> &[u8]
);

#[bridge_fn_void]
fn Cds2ClientState_CompleteHandshake(
    cli: &mut Cds2ClientState,
    handshake_received: &[u8],
) -> Result<()> {
    cli.complete_handshake(handshake_received)
}

#[bridge_fn_buffer]
fn Cds2ClientState_EstablishedSend(
    cli: &mut Cds2ClientState,
    plaintext_to_send: &[u8],
) -> Result<Vec<u8>> {
    cli.established_send(plaintext_to_send)
}

#[bridge_fn_buffer]
fn Cds2ClientState_EstablishedRecv(
    cli: &mut Cds2ClientState,
    received_ciphertext: &[u8],
) -> Result<Vec<u8>> {
    cli.established_recv(received_ciphertext)
}

#[cfg(all(not(target_os = "android"), feature = "jni"))]
pub struct Cds2Metrics(pub HashMap<String, i64>);

#[cfg(not(target_os = "android"))]
#[bridge_fn(ffi = false, node = false)]
fn Cds2Metrics_extract(attestation_msg: &[u8]) -> Result<Cds2Metrics> {
    cds2::extract_metrics(attestation_msg).map(Cds2Metrics)
}
