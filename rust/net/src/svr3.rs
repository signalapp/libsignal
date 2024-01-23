//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::enclave::{HasConnections, PpssSetup};
use crate::infra::errors::NetError;
use crate::infra::ws::{run_attested_interaction, AttestedConnectionError};
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
#[derive(Debug, Eq, PartialEq, displaydoc::Display)]
pub enum DeserializeError {
    /// Unexpected version {0}
    BadVersion(u8),
    /// Unsupported serialization format
    BadFormat,
}

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

#[derive(Debug, displaydoc::Display)]
pub enum Error {
    /// SVR3 error: {0}
    Logic(libsignal_svr3::Error),
    /// Network error: {0}
    Network(String),
}

impl From<libsignal_svr3::Error> for Error {
    fn from(err: libsignal_svr3::Error) -> Self {
        Self::Logic(err)
    }
}

impl From<AttestedConnectionError> for Error {
    fn from(err: AttestedConnectionError) -> Self {
        Self::Network(format!("{:?}", err))
    }
}

impl From<NetError> for Error {
    fn from(err: NetError) -> Self {
        Self::Network(err.to_string())
    }
}

#[async_trait(?Send)]
pub trait PpssOps: PpssSetup {
    async fn backup(
        connections: &mut Self::Connections,
        password: &str,
        secret: [u8; 32],
        max_tries: NonZeroU32,
        rng: &mut impl CryptoRngCore,
    ) -> Result<OpaqueMaskedShareSet, Error>;

    async fn restore(
        connections: &mut Self::Connections,
        password: &str,
        share_set: OpaqueMaskedShareSet,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 32], Error>;
}

#[async_trait(?Send)]
impl<Env: PpssSetup> PpssOps for Env {
    async fn backup(
        connections: &mut Self::Connections,
        password: &str,
        secret: [u8; 32],
        max_tries: NonZeroU32,
        rng: &mut impl CryptoRngCore,
    ) -> Result<OpaqueMaskedShareSet, Error> {
        let server_ids = Self::server_ids().as_mut().to_owned();
        let backup = Backup::new(&server_ids, password, secret, max_tries, rng)?;
        let mut connections = connections.get_connections();
        let futures = connections
            .as_mut()
            .iter_mut()
            .zip(&backup.requests)
            .map(|(connection, request)| run_attested_interaction(connection, request));
        let result = try_join_all(futures).await?;
        let responses = result
            .into_iter()
            .map(|next_or_close| next_or_close.next_or(NetError::Failure))
            .collect::<Result<Vec<_>, _>>()?;
        let share_set = backup.finalize(rng, &responses)?;
        Ok(OpaqueMaskedShareSet::new(share_set))
    }

    async fn restore(
        connections: &mut Self::Connections,
        password: &str,
        share_set: OpaqueMaskedShareSet,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 32], Error> {
        let restore = Restore::new(password, share_set.into_inner(), rng)?;
        let mut connections = connections.get_connections();
        let futures = connections
            .as_mut()
            .iter_mut()
            .zip(&restore.requests)
            .map(|(connection, request)| run_attested_interaction(connection, request));
        let result = try_join_all(futures).await?;
        let responses = result
            .into_iter()
            .map(|next_or_close| next_or_close.next_or(NetError::Failure))
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
