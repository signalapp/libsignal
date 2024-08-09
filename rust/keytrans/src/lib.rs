//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
mod commitments;
mod guide;
mod implicit;
mod left_balanced;
mod log;
mod prefix;
mod verify;
mod vrf;
mod wire;

use std::collections::HashMap;

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey as SigPublicKey;
use prost::{DecodeError, Message};

pub use verify::{
    truncate_search_response, verify_distinguished, verify_monitor, verify_search, verify_update,
};
use vrf::PublicKey as VrfPublicKey;
pub use wire::{
    Consistency, FullTreeHead, MonitorKey, MonitorRequest, MonitorResponse, SearchRequest,
    SearchResponse, TreeHead, UpdateRequest, UpdateResponse, UpdateValue,
};

/// DeploymentMode specifies the way that a transparency log is deployed.
#[derive(PartialEq, Clone, Copy)]
pub enum DeploymentMode {
    ContactMonitoring,
    ThirdPartyManagement(SigPublicKey),
    ThirdPartyAuditing(SigPublicKey),
}

impl DeploymentMode {
    fn byte(&self) -> u8 {
        match self {
            DeploymentMode::ContactMonitoring => 1,
            DeploymentMode::ThirdPartyManagement(_) => 2,
            DeploymentMode::ThirdPartyAuditing(_) => 3,
        }
    }

    fn get_associated_key(&self) -> Option<&SigPublicKey> {
        match self {
            DeploymentMode::ContactMonitoring => None,
            DeploymentMode::ThirdPartyManagement(key) => Some(key),
            DeploymentMode::ThirdPartyAuditing(key) => Some(key),
        }
    }
}

/// PublicConfig wraps the cryptographic keys needed to interact with a
/// transparency tree.
#[derive(Clone)]
pub struct PublicConfig {
    pub mode: DeploymentMode,
    pub signature_key: SigPublicKey,
    pub vrf_key: VrfPublicKey,
}

/// MonitoringData is the structure retained for each key in the KT server being
/// monitored.
pub struct MonitoringData {
    /// The VRF output on the search key.
    pub index: [u8; 32],
    /// The initial position of the key in the log.
    pub pos: u64,
    /// Map from position in log to observed version.
    pub ptrs: HashMap<u64, u32>,
    /// Whether this client owns the key.
    pub owned: bool,
}

impl MonitoringData {
    /// The smallest tree size where monitoring would be valuable.
    pub fn next_monitor(&self) -> u64 {
        implicit::next_monitor(&self.entries())
    }

    /// The entries field of a MonitorKey structure.
    pub fn entries(&self) -> Vec<u64> {
        let mut out: Vec<u64> = self.ptrs.keys().copied().collect();
        out.sort();
        out
    }
}

/// Log store operation failed: {0}
#[derive(Debug, displaydoc::Display)]
pub struct LogStoreError(String);

impl From<DecodeError> for LogStoreError {
    fn from(err: DecodeError) -> Self {
        Self(err.to_string())
    }
}

/// LogStore is the trait implemented by clients for storing local monitoring
/// data specific to a single log.
#[async_trait(?Send)]
pub trait LogStore {
    async fn public_config(&self) -> Result<PublicConfig, LogStoreError>;

    async fn get_last_tree_head(&self) -> Result<Option<(TreeHead, [u8; 32])>, LogStoreError>;
    async fn set_last_tree_head(
        &mut self,
        head: TreeHead,
        root: [u8; 32],
    ) -> Result<(), LogStoreError>;

    async fn get_data(&self, key: &str) -> Result<Option<MonitoringData>, LogStoreError>;
    async fn set_data(&mut self, key: &str, data: MonitoringData) -> Result<(), LogStoreError>;
}

/// SimplifiedLogStore is a simpler version of the LogStore trait that clients
/// can implement to avoid needing to deal with serialization themselves.
#[async_trait(?Send)]
pub trait SimplifiedLogStore {
    async fn public_config(&self) -> Result<PublicConfig, LogStoreError>;

    async fn get_raw_tree_head(&self) -> Result<Option<Vec<u8>>, LogStoreError>;
    async fn set_raw_tree_head(&mut self, data: &[u8]) -> Result<(), LogStoreError>;

    async fn get_raw_data(&self, key: &str) -> Result<Option<Vec<u8>>, LogStoreError>;
    async fn set_raw_data(
        &mut self,
        key: &str,
        data: &[u8],
        next_monitor: u64,
    ) -> Result<(), LogStoreError>;
    async fn list_keys(&self) -> Result<Vec<String>, LogStoreError>;

    fn as_log_store(&mut self) -> &mut dyn LogStore;
}

#[async_trait(?Send)]
impl<T: SimplifiedLogStore + ?Sized> LogStore for T {
    async fn public_config(&self) -> Result<PublicConfig, LogStoreError> {
        self.public_config().await
    }

    async fn get_last_tree_head(&self) -> Result<Option<(TreeHead, [u8; 32])>, LogStoreError> {
        self.get_raw_tree_head()
            .await?
            .map(|data| {
                let stored = wire::StoredTreeHead::decode(data.as_slice())?;
                let tree_head = stored
                    .tree_head
                    .ok_or_else(|| LogStoreError("malformed tree head found".to_string()))?;
                let root = stored
                    .root
                    .try_into()
                    .map_err(|_| LogStoreError("malformed root found".to_string()))?;
                Ok((tree_head, root))
            })
            .transpose()
    }

    async fn set_last_tree_head(
        &mut self,
        head: TreeHead,
        root: [u8; 32],
    ) -> Result<(), LogStoreError> {
        let raw = wire::StoredTreeHead {
            tree_head: Some(head),
            root: root.to_vec(),
        }
        .encode_to_vec();
        self.set_raw_tree_head(&raw).await
    }

    async fn get_data(&self, key: &str) -> Result<Option<MonitoringData>, LogStoreError> {
        self.get_raw_data(key)
            .await?
            .map(|data| {
                let stored = wire::StoredMonitoringData::decode(data.as_slice())?;
                Ok(MonitoringData {
                    index: stored
                        .index
                        .try_into()
                        .map_err(|_| LogStoreError("malformed index found".to_string()))?,
                    pos: stored.pos,
                    ptrs: stored.ptrs,
                    owned: stored.owned,
                })
            })
            .transpose()
    }

    async fn set_data(&mut self, key: &str, data: MonitoringData) -> Result<(), LogStoreError> {
        let next_monitor = data.next_monitor();
        let raw = wire::StoredMonitoringData {
            index: data.index.to_vec(),
            pos: data.pos,
            ptrs: data.ptrs,
            owned: data.owned,
        }
        .encode_to_vec();
        self.set_raw_data(key, &raw, next_monitor).await
    }
}
