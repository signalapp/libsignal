//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Most of the traits in this module are likely to be used together
//! therefore the module exists as a sort of a "prelude" to make importing them
//! all in bulk easier.

use std::num::NonZeroU32;

use async_trait::async_trait;
use libsignal_svr3::EvaluationResult;
use rand_core::CryptoRngCore;

use super::{ppss_ops, Error, OpaqueMaskedShareSet};
use crate::enclave::PpssSetup;

#[async_trait]
pub trait Backup {
    async fn backup(
        &self,
        password: &str,
        secret: [u8; 32],
        max_tries: NonZeroU32,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<OpaqueMaskedShareSet, Error>;
}

#[async_trait]
pub trait Restore {
    async fn restore(
        &self,
        password: &str,
        share_set: OpaqueMaskedShareSet,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<EvaluationResult, Error>;
}

#[async_trait]
pub trait Query {
    async fn query(&self) -> Result<u32, Error>;
}

#[async_trait]
pub trait Remove {
    async fn remove(&self) -> Result<(), Error>;
}

#[async_trait]
pub trait Rotate {
    async fn rotate(
        &self,
        share_set: OpaqueMaskedShareSet,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<(), Error>;
}

#[async_trait]
pub trait Svr3Connect {
    type Env: PpssSetup;
    async fn connect(&self) -> <Self::Env as PpssSetup>::ConnectionResults;
}

#[async_trait]
impl<T> Backup for T
where
    T: Svr3Connect + Sync,
{
    async fn backup(
        &self,
        password: &str,
        secret: [u8; 32],
        max_tries: NonZeroU32,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<OpaqueMaskedShareSet, Error> {
        ppss_ops::do_backup::<T::Env>(self.connect().await, password, secret, max_tries, rng).await
    }
}

#[async_trait]
impl<T> Restore for T
where
    T: Svr3Connect + Sync,
{
    async fn restore(
        &self,
        password: &str,
        share_set: OpaqueMaskedShareSet,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<EvaluationResult, Error> {
        ppss_ops::do_restore(self.connect().await, password, share_set, rng).await
    }
}

#[async_trait]
impl<T> Remove for T
where
    T: Svr3Connect + Sync,
{
    async fn remove(&self) -> Result<(), Error> {
        ppss_ops::do_remove(self.connect().await).await
    }
}

#[async_trait]
impl<T> Query for T
where
    T: Svr3Connect + Sync,
{
    async fn query(&self) -> Result<u32, Error> {
        ppss_ops::do_query(self.connect().await).await
    }
}

#[async_trait]
impl<T> Rotate for T
where
    T: Svr3Connect + Sync,
{
    async fn rotate(
        &self,
        share_set: OpaqueMaskedShareSet,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<(), Error> {
        ppss_ops::do_rotate(self.connect().await, share_set, rng).await
    }
}
