//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;

use displaydoc::Display;

use crate::client_connection::ClientConnection;
use crate::{client_connection, dcap, nitro, snow_resolver};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct AttestationError {
    message: String,
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for AttestationError {}

impl From<dcap::Error> for AttestationError {
    fn from(e: dcap::Error) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

/// Error types for an enclave noise session.
#[derive(Display, Debug)]
pub enum Error {
    /// failure to attest remote enclave: {0:?}
    AttestationError(AttestationError),
    /// failure to communicate on established Noise channel to the enclave: {0}
    NoiseError(client_connection::Error),
    /// failure to complete Noise handshake to the enclave: {0}
    NoiseHandshakeError(snow::Error),
    /// attestation data invalid: {reason}
    AttestationDataError { reason: String },
    /// invalid bridge state
    InvalidBridgeStateError,
}

impl From<snow::Error> for Error {
    fn from(e: snow::Error) -> Self {
        Error::NoiseHandshakeError(e)
    }
}

impl From<AttestationError> for Error {
    fn from(err: AttestationError) -> Error {
        Error::AttestationError(err)
    }
}

impl From<client_connection::Error> for Error {
    fn from(err: client_connection::Error) -> Self {
        Error::NoiseError(err)
    }
}

impl From<prost::DecodeError> for Error {
    fn from(err: prost::DecodeError) -> Self {
        Error::AttestationDataError {
            reason: err.to_string(),
        }
    }
}

impl From<nitro::NitroError> for AttestationError {
    fn from(err: nitro::NitroError) -> Self {
        AttestationError {
            message: err.to_string(),
        }
    }
}

impl From<nitro::NitroError> for Error {
    fn from(err: nitro::NitroError) -> Self {
        Self::AttestationError(err.into())
    }
}

/// A noise handshaker that can be used to build a [client_connection::ClientConnection]
///
/// Callers provide an attestation that must contain the remote enclave's public key. If the
/// attestation is valid, this public key will be used to generate a noise NK handshake (with
/// the caller acting as the initiator) via [Handshake::initial_request]. When
/// a handshake response is received the handshake can be completed with
/// [Handshake::complete] to build a [client_connection::ClientConnection] that
/// can be used to exchange arbitrary encrypted payloads with the remote enclave.
///
/// ```pseudocode
///   let websocket = ... open websocket ...
///   let attestation_msg = websocket.recv();
///   let (evidence, endoresments) = parse(attestation_msg);
///   let mut handshake = Handshake::new(
///     mrenclave, evidence, endorsements, acceptable_sw_advisories, current_time)?;
///   websocket.send(handshaker.initial_request());
///   let initial_response = websocket.recv(...);
///   let conn = handshaker.complete(initial_response);
/// ```
pub struct Handshake {
    pub(crate) handshake: snow::HandshakeState,
    pub(crate) initial_request: Vec<u8>,
    pub(crate) claims: Claims,
}

impl Handshake {
    /// Initial message from client for noise handshake.
    pub fn initial_request(&self) -> &[u8] {
        &self.initial_request
    }

    /// custom claims extracted from the attestation
    pub fn custom_claims(&self) -> &HashMap<String, Vec<u8>> {
        &self.claims.custom
    }

    /// Completes client connection initiation, returns a valid client connection.
    pub fn complete(mut self, initial_received: &[u8]) -> Result<ClientConnection> {
        self.handshake.read_message(initial_received, &mut [])?;
        let transport = self.handshake.into_transport_mode()?;
        log::info!("Successfully completed attested connection");
        Ok(ClientConnection { transport })
    }

    pub(crate) fn with_claims(claims: Claims) -> Result<Self> {
        let mut handshake = snow::Builder::with_resolver(
            client_connection::NOISE_PATTERN.parse().expect("valid"),
            Box::new(snow_resolver::Resolver),
        )
        .remote_public_key(&claims.public_key)
        .build_initiator()?;
        let mut initial_request = vec![0u8; client_connection::NOISE_HANDSHAKE_OVERHEAD];
        // We send an empty message, but the round-trip to the server and back is still required
        // in order to complete the noise handshake. If we needed some initial payload we could
        // add it here in future.
        let size = handshake.write_message(&[], &mut initial_request)?;
        initial_request.truncate(size);
        Ok(Self {
            handshake,
            initial_request,
            claims,
        })
    }
}

pub struct Claims {
    public_key: Vec<u8>,
    custom: HashMap<String, Vec<u8>>,
}

impl Claims {
    pub fn from_custom_claims(mut claims: HashMap<String, Vec<u8>>) -> Result<Self> {
        let public_key = claims
            .remove("pk")
            .ok_or_else(|| Error::AttestationDataError {
                reason: "pk field is missing from the claims".to_string(),
            })?;
        Ok(Self {
            public_key,
            custom: claims,
        })
    }

    pub fn from_public_key(public_key: Vec<u8>) -> Result<Self> {
        Ok(Self {
            public_key,
            custom: HashMap::default(),
        })
    }
}
