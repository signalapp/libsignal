//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;

use displaydoc::Display;
use prost::Message;

use crate::client_connection::ClientConnection;
use crate::svr2::RaftConfig;
use crate::tpm2snp::Tpm2Error;
use crate::{client_connection, dcap, nitro, proto, snow_resolver};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
/// Failure to attest remote enclave.
#[error("{message}")]
pub struct AttestationError {
    message: String,
}

impl From<dcap::Error> for AttestationError {
    fn from(e: dcap::Error) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

/// Error types for an enclave noise session.
#[derive(Display, Debug, thiserror::Error)]
pub enum Error {
    /// failure to attest remote enclave: {0:?}
    AttestationError(#[from] AttestationError),
    /// failure to communicate on established Noise channel to the enclave: {0}
    NoiseError(#[from] client_connection::Error),
    /// failure to complete Noise handshake to the enclave: {0}
    NoiseHandshakeError(#[from] snow::Error),
    /// attestation data invalid: {reason}
    AttestationDataError { reason: String },
    /// invalid bridge state
    InvalidBridgeStateError,
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

impl From<Tpm2Error> for AttestationError {
    fn from(err: Tpm2Error) -> Self {
        AttestationError {
            message: err.to_string(),
        }
    }
}

impl From<Tpm2Error> for Error {
    fn from(err: Tpm2Error) -> Self {
        Self::AttestationError(err.into())
    }
}

pub enum HandshakeType {
    PreQuantum,
    PostQuantum,
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
///   let (evidence, endorsements) = parse(attestation_msg);
///   let mut handshake = Handshake::new(
///     mrenclave, evidence, endorsements, acceptable_sw_advisories, current_time)?;
///   websocket.send(handshaker.initial_request());
///   let initial_response = websocket.recv(...);
///   let conn = handshaker.complete(initial_response);
/// ```
pub struct Handshake {
    handshake: snow::HandshakeState,
    initial_request: Vec<u8>,
    claims: Claims,
}

impl Handshake {
    /// Initial message from client for noise handshake.
    pub fn initial_request(&self) -> &[u8] {
        &self.initial_request
    }

    /// Completes client connection initiation, returns a valid client connection.
    pub fn complete(mut self, initial_received: &[u8]) -> Result<ClientConnection> {
        self.handshake.read_message(initial_received, &mut [])?;
        let handshake_hash = self.handshake.get_handshake_hash().to_vec();
        let transport = self.handshake.into_transport_mode()?;
        log::info!("Successfully completed attested connection");
        Ok(ClientConnection {
            handshake_hash,
            transport,
        })
    }

    pub(crate) fn with_claims(claims: Claims, typ: HandshakeType) -> Result<UnvalidatedHandshake> {
        let pattern = match typ {
            HandshakeType::PreQuantum => client_connection::NOISE_PATTERN,
            HandshakeType::PostQuantum => client_connection::NOISE_PATTERN_HFS,
        };
        let mut handshake = snow::Builder::with_resolver(
            pattern.parse().expect("valid"),
            Box::new(snow_resolver::Resolver),
        )
        .remote_public_key(&claims.public_key)
        .build_initiator()
        .map_err(|_| {
            // The only thing that can go wrong is that claims.public_key is invalid, which isn't a
            // fault in the Noise handshake. Produce a data error instead to indicate this (and for
            // simpler exception logic in the apps).
            //
            // In practice the current version of Noise does not even check this up front, so we
            // can't test this. But a future version could and the previous reasoning stands.
            Error::AttestationDataError {
                reason: "invalid public key".to_string(),
            }
        })?;
        let mut initial_request = vec![0u8; client_connection::NOISE_HANDSHAKE_OVERHEAD];
        // We send an empty message, but the round-trip to the server and back is still required
        // in order to complete the noise handshake. If we needed some initial payload we could
        // add it here in future.
        let size = handshake
            .write_message(&[], &mut initial_request)
            .expect("properly sized");
        initial_request.truncate(size);
        Ok(UnvalidatedHandshake(Self {
            handshake,
            initial_request,
            claims,
        }))
    }
}

pub(crate) struct UnvalidatedHandshake(Handshake);

impl UnvalidatedHandshake {
    pub(crate) fn validate(self, expected_raft_config: &RaftConfig) -> Result<Handshake> {
        let actual_config =
            &self
                .0
                .claims
                .raft_group_config
                .as_ref()
                .ok_or(Error::AttestationDataError {
                    reason: "Claims must contain a raft group config".to_string(),
                })?;
        if expected_raft_config != *actual_config {
            return Err(Error::AttestationDataError {
                reason: format!(
                    "Unexpected raft config {:?} (expected {:?})",
                    actual_config, expected_raft_config
                ),
            });
        }
        Ok(self.0)
    }

    pub(crate) fn skip_raft_validation(self) -> Handshake {
        self.0
    }
}

pub struct Claims {
    pub(crate) public_key: Vec<u8>,
    pub(crate) raft_group_config: Option<proto::svr::RaftGroupConfig>,
    #[allow(dead_code)]
    pub(crate) custom: HashMap<String, Vec<u8>>,
}

impl Claims {
    pub fn from_custom_claims(mut claims: HashMap<String, Vec<u8>>) -> Result<Self> {
        let public_key = claims
            .remove("pk")
            .ok_or_else(|| Error::AttestationDataError {
                reason: "pk field is missing from the claims".to_string(),
            })?;

        let raft_group_config = claims
            .remove("config")
            .map(|bytes| proto::svr::RaftGroupConfig::decode(bytes.as_slice()))
            .transpose()?;

        Ok(Self {
            public_key,
            raft_group_config,
            custom: claims,
        })
    }

    pub fn from_attestation_data(data: proto::svr::AttestationData) -> Result<Self> {
        let raft_group_config = data
            .group_config
            .ok_or_else(|| Error::AttestationDataError {
                reason: "RaftGroupConfig is missing from the AttestationData".to_string(),
            })?;
        let raft_group_config = Some(raft_group_config);
        Ok(Self {
            public_key: data.public_key,
            raft_group_config,
            custom: HashMap::default(),
        })
    }
}
