//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::enclave::{HasConnections, PpssSetup};
use crate::infra::errors::NetError;
use crate::infra::ws::{run_attested_interaction, AttestedConnectionError};
use async_trait::async_trait;
use futures_util::future::try_join_all;
use libsignal_svr3::{Backup, MaskedShareSet, Restore};
use rand::{CryptoRng, Rng};

#[derive(Clone)]
pub struct OpaqueMaskedShareSet {
    inner: MaskedShareSet,
}

#[derive(Debug)]
pub struct SerializeError;
#[derive(Debug)]
pub struct DeserializeError;

impl OpaqueMaskedShareSet {
    pub(crate) fn into_inner(self) -> MaskedShareSet {
        self.inner
    }

    // OpaqueMaskedShareSet should be presented to the clients as an opaque blob,
    // therefore serialize/deserialize should be the only public APIs for it.
    // TODO: Add version to the serialized data to allow for format evolution
    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        bincode::serialize(&self.inner).map_err(|_| SerializeError)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        match bincode::deserialize(bytes) {
            Ok(inner) => Ok(Self { inner }),
            Err(_) => Err(DeserializeError),
        }
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
        max_tries: u32,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<OpaqueMaskedShareSet, Error>;

    async fn restore(
        connections: &mut Self::Connections,
        password: &str,
        share_set: OpaqueMaskedShareSet,
    ) -> Result<[u8; 32], Error>;
}

#[async_trait(?Send)]
impl<Env: PpssSetup> PpssOps for Env {
    async fn backup(
        connections: &mut Self::Connections,
        password: &str,
        secret: [u8; 32],
        max_tries: u32,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<OpaqueMaskedShareSet, Error> {
        let server_ids = Self::server_ids().as_mut().to_owned();
        let backup = Backup::new(&server_ids, password, secret, max_tries)?;
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
        Ok(OpaqueMaskedShareSet { inner: share_set })
    }

    async fn restore(
        connections: &mut Self::Connections,
        password: &str,
        share_set: OpaqueMaskedShareSet,
    ) -> Result<[u8; 32], Error> {
        let restore = Restore::new(password, share_set.into_inner())?;
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
