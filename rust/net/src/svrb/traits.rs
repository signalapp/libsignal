//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Most of the traits in this module are likely to be used together
//! therefore the module exists as a sort of a "prelude" to make importing them
//! all in bulk easier.

use async_trait::async_trait;

use super::{ppss_ops, Backup4, Error, Secret};
use crate::enclave::PpssSetup;

#[async_trait]
pub trait Backup {
    fn prepare(&self, password: &[u8]) -> Backup4;
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

#[async_trait]
impl<T> Backup for T
where
    T: SvrBConnect + Sync,
{
    fn prepare(&self, password: &[u8]) -> Backup4 {
        ppss_ops::do_prepare::<T::Env>(password)
    }
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
