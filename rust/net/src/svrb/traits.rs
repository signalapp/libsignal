//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Most of the traits in this module are likely to be used together
//! therefore the module exists as a sort of a "prelude" to make importing them
//! all in bulk easier.

use async_trait::async_trait;

use super::{Backup4, Error, Secret, ppss_ops};
use crate::enclave::PpssSetup;

pub trait Prepare {
    fn prepare(&self, password: &[u8]) -> Backup4;
}

#[async_trait]
pub trait Backup {
    async fn finalize(&self, backup: &Backup4) -> Result<(), Error>;
}

#[async_trait]
pub trait Restore {
    async fn restore(&self, password: &[u8]) -> Result<Secret, Error>;
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
pub trait SvrBConnect {
    type Env: PpssSetup;
    async fn connect(&self) -> <Self::Env as PpssSetup>::ConnectionResults;
}

impl<T> Prepare for T
where
    T: SvrBConnect,
{
    fn prepare(&self, password: &[u8]) -> Backup4 {
        ppss_ops::do_prepare::<T::Env>(password)
    }
}

/// So we can `prepare` without being able to `connect`.
impl Prepare for crate::env::SvrBEnv<'_> {
    fn prepare(&self, password: &[u8]) -> libsignal_svrb::Backup4 {
        ppss_ops::do_prepare::<Self>(password)
    }
}

#[async_trait]
impl<T> Backup for T
where
    T: SvrBConnect + Sync,
{
    async fn finalize(&self, backup: &Backup4) -> Result<(), Error> {
        ppss_ops::do_backup::<T::Env>(self.connect().await, backup).await
    }
}

#[async_trait]
impl<T> Restore for T
where
    T: SvrBConnect + Sync,
{
    async fn restore(&self, password: &[u8]) -> Result<Secret, Error> {
        ppss_ops::do_restore::<T::Env>(self.connect().await, password).await
    }
}

#[async_trait]
impl<T> Remove for T
where
    T: SvrBConnect + Sync,
{
    async fn remove(&self) -> Result<(), Error> {
        ppss_ops::do_remove(self.connect().await).await
    }
}

#[async_trait]
impl<T> Query for T
where
    T: SvrBConnect + Sync,
{
    async fn query(&self) -> Result<u32, Error> {
        ppss_ops::do_query(self.connect().await).await
    }
}
