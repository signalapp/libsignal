//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use thiserror::Error;

use crate::enclave::{IntoConnections, PpssSetup};
use crate::infra::errors::LogSafeDisplay;
use crate::infra::ws::{
    run_attested_interaction, AttestedConnectionError, WebSocketConnectError, WebSocketServiceError,
};
use crate::infra::AsyncDuplexStream;
use async_trait::async_trait;
use bincode::Options as _;
use futures_util::future::try_join_all;
use libsignal_svr3::{Backup, MaskedShareSet, Restore};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;

const MASKED_SHARE_SET_FORMAT: u8 = 0;

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct OpaqueMaskedShareSet {
    inner: SerializableMaskedShareSet,
}

// Non pub version of ppss::MaskedShareSet used for serialization
#[derive(Clone, Serialize, Deserialize, Debug)]
struct SerializableMaskedShareSet {
    server_ids: Vec<u64>,
    masked_shares: Vec<[u8; 32]>,
    commitment: [u8; 32],
}

impl From<MaskedShareSet> for SerializableMaskedShareSet {
    fn from(value: MaskedShareSet) -> Self {
        Self {
            server_ids: value.server_ids,
            masked_shares: value.masked_shares,
            commitment: value.commitment,
        }
    }
}

impl SerializableMaskedShareSet {
    fn into(self) -> MaskedShareSet {
        MaskedShareSet {
            server_ids: self.server_ids,
            masked_shares: self.masked_shares,
            commitment: self.commitment,
        }
    }
}

#[derive(Debug)]
pub struct SerializeError;

#[derive(Debug, Eq, PartialEq, displaydoc::Display, Error)]
pub enum DeserializeError {
    /// Unexpected OpaqueMaskedShareSet serialization format version {0}
    BadVersion(u8),
    /// Unsupported OpaqueMaskedShareSet serialization format
    BadFormat,
}

impl LogSafeDisplay for DeserializeError {}

impl OpaqueMaskedShareSet {
    fn new(inner: MaskedShareSet) -> Self {
        Self {
            inner: inner.into(),
        }
    }
    fn into_inner(self) -> MaskedShareSet {
        self.inner.into()
    }

    // OpaqueMaskedShareSet should be presented to the clients as an opaque blob,
    // therefore serialize/deserialize should be the only public APIs for it.
    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        let mut buf = vec![MASKED_SHARE_SET_FORMAT];

        Self::bincode_options()
            .serialize_into(&mut buf, &self.inner)
            .map_err(|_| SerializeError)?;
        Ok(buf)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        match bytes {
            [] => Err(DeserializeError::BadFormat),
            [MASKED_SHARE_SET_FORMAT, data @ ..] => Self::bincode_deserialize(data),
            [v, ..] => Err(DeserializeError::BadVersion(*v)),
        }
    }

    fn bincode_options() -> impl bincode::Options {
        // Using options to reject possible trailing bytes but retain the fixed representation for integers.
        // See https://docs.rs/bincode/latest/bincode/config/index.html#options-struct-vs-bincode-functions
        bincode::config::DefaultOptions::new()
            .reject_trailing_bytes()
            .with_fixint_encoding()
    }

    fn bincode_deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        let inner = Self::bincode_options()
            .deserialize(bytes)
            .map_err(|_| DeserializeError::BadFormat)?;
        Ok(Self { inner })
    }
}

/// SVR3-specific error type
///
/// In its essence it is simply a union of three other error types:
/// - libsignal_svr3::Error for the errors originating in the PPSS implementation. Most of them are
/// unlikely due to the way higher level APIs invoke the lower-level primitives from
/// libsignal_svr3.
/// - DeserializeError for the errors deserializing the OpaqueMaskedShareSet that is stored as a
/// simple blob by the clients and may be corrupted.
/// - libsignal_net::svr::Error for network related errors.
#[derive(Debug, Error, displaydoc::Display)]
#[ignore_extra_doc_attributes]
pub enum Error {
    /// Connection error: {0}
    Connect(WebSocketConnectError),
    /// Network error: {0}
    Service(#[from] WebSocketServiceError),
    /// Protocol error after establishing a connection: {0}
    Protocol(String),
    /// Enclave attestation failed: {0}
    AttestationError(attest::enclave::Error),
    /// SVR3 request failed with status {0}
    RequestFailed(libsignal_svr3::ErrorStatus),
    /// Failure to restore data
    ///
    /// This could be caused by an invalid password or share set.
    RestoreFailed,
    /// Restore request failed with MISSING status,
    ///
    /// This could mean either the data was never backed-up or we ran out of attempts to restore
    /// it.
    DataMissing,
    /// Connect timed out
    ConnectionTimedOut,
}

impl From<DeserializeError> for Error {
    fn from(err: DeserializeError) -> Self {
        Self::Protocol(format!("DeserializationError {err}"))
    }
}

impl From<attest::enclave::Error> for Error {
    fn from(err: attest::enclave::Error) -> Self {
        Self::AttestationError(err)
    }
}

impl From<libsignal_svr3::Error> for Error {
    fn from(err: libsignal_svr3::Error) -> Self {
        use libsignal_svr3::{Error as LogicError, PPSSError};
        match err {
            LogicError::Ppss(PPSSError::InvalidCommitment) => Self::RestoreFailed,
            LogicError::BadResponseStatus(libsignal_svr3::ErrorStatus::Missing) => {
                Self::DataMissing
            }
            LogicError::Oprf(_)
            | LogicError::Ppss(_)
            | LogicError::BadData
            | LogicError::BadResponse
            | LogicError::BadResponseStatus(_) => Self::Protocol(err.to_string()),
        }
    }
}

impl From<super::svr::Error> for Error {
    fn from(err: super::svr::Error) -> Self {
        use super::svr::Error as SvrError;
        match err {
            SvrError::WebSocketConnect(inner) => Self::Connect(inner),
            SvrError::WebSocket(inner) => Self::Service(inner),
            SvrError::Protocol => Self::Protocol("General SVR protocol error".to_string()),
            SvrError::AttestationError(inner) => Self::AttestationError(inner),
            SvrError::ConnectionTimedOut => Self::ConnectionTimedOut,
        }
    }
}

impl From<AttestedConnectionError> for Error {
    fn from(err: AttestedConnectionError) -> Self {
        Self::from(super::svr::Error::from(err))
    }
}

#[async_trait]
pub trait PpssOps<S>: PpssSetup<S> {
    async fn backup(
        connections: Self::Connections,
        password: &str,
        secret: [u8; 32],
        max_tries: NonZeroU32,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<OpaqueMaskedShareSet, Error>;

    async fn restore(
        connections: Self::Connections,
        password: &str,
        share_set: OpaqueMaskedShareSet,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<[u8; 32], Error>;
}

#[async_trait]
impl<S: AsyncDuplexStream + 'static, Env: PpssSetup<S>> PpssOps<S> for Env {
    async fn backup(
        connections: Self::Connections,
        password: &str,
        secret: [u8; 32],
        max_tries: NonZeroU32,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<OpaqueMaskedShareSet, Error> {
        let server_ids = Self::server_ids();
        let backup = Backup::new(server_ids.as_ref(), password, secret, max_tries, rng)?;
        let mut connections = connections.into_connections();
        let futures = connections
            .as_mut()
            .iter_mut()
            .zip(&backup.requests)
            .map(|(connection, request)| run_attested_interaction(connection, request));
        let result = try_join_all(futures).await?;
        let responses = result
            .into_iter()
            .enumerate()
            .map(|(i, next_or_close)| {
                let remote_address = connections.as_ref()[i].remote_address();
                next_or_close.next_or(Error::Protocol(format!(
                    "no response from {remote_address}"
                )))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let share_set = backup.finalize(rng, &responses)?;
        Ok(OpaqueMaskedShareSet::new(share_set))
    }

    async fn restore(
        connections: Self::Connections,
        password: &str,
        share_set: OpaqueMaskedShareSet,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<[u8; 32], Error> {
        let restore = Restore::new(password, share_set.into_inner(), rng)?;
        let mut connections = connections.into_connections();
        let futures = connections
            .as_mut()
            .iter_mut()
            .zip(&restore.requests)
            .map(|(connection, request)| run_attested_interaction(connection, request));
        let result = try_join_all(futures).await?;
        let responses = result
            .into_iter()
            .enumerate()
            .map(|(i, next_or_close)| {
                let remote_address = connections.as_ref()[i].remote_address();
                next_or_close.next_or(Error::Protocol(format!(
                    "no response from {remote_address}"
                )))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(restore.finalize(&responses)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn new_empty_share_set() -> OpaqueMaskedShareSet {
        OpaqueMaskedShareSet {
            inner: SerializableMaskedShareSet {
                server_ids: vec![],
                masked_shares: vec![],
                commitment: [0; 32],
            },
        }
    }

    #[test]
    fn serialized_share_set_has_version() {
        let bytes = new_empty_share_set().serialize().expect("can serialize");
        assert_eq!(MASKED_SHARE_SET_FORMAT, bytes[0]);
    }

    #[test]
    fn deserialize_share_set_supported_version() {
        let there = new_empty_share_set().serialize().expect("can serialize");
        let and_back = OpaqueMaskedShareSet::deserialize(&there);
        assert!(and_back.is_ok(), "Should be able to deserialize");
    }

    #[test]
    fn deserialize_share_set_bad_version() {
        let there = {
            let mut bytes = new_empty_share_set().serialize().expect("can serialize");
            bytes[0] = 0xff;
            bytes
        };
        let and_back = OpaqueMaskedShareSet::deserialize(&there);
        assert!(matches!(
            and_back.expect_err("Unexpected deserialization success"),
            DeserializeError::BadVersion(_),
        ));
    }
}
