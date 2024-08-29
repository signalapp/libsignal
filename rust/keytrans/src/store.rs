//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use prost::{DecodeError, Message};

use crate::{wire, MonitoringData, TreeHead};

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
pub trait LogStore {
    fn get_last_tree_head(&self) -> Result<Option<(TreeHead, [u8; 32])>, LogStoreError>;
    fn set_last_tree_head(&mut self, head: TreeHead, root: [u8; 32]) -> Result<(), LogStoreError>;

    fn get_data(&self, key: &[u8]) -> Result<Option<MonitoringData>, LogStoreError>;
    fn set_data(&mut self, key: &[u8], data: MonitoringData) -> Result<(), LogStoreError>;
}

/// SimplifiedLogStore is a simpler version of the LogStore trait that clients
/// can implement to avoid needing to deal with serialization themselves.
trait SimplifiedLogStore {
    fn get_raw_tree_head(&self) -> Result<Option<Vec<u8>>, LogStoreError>;
    fn set_raw_tree_head(&mut self, data: &[u8]) -> Result<(), LogStoreError>;

    fn get_raw_data(&self, key: &[u8]) -> Result<Option<Vec<u8>>, LogStoreError>;
    fn set_raw_data(
        &mut self,
        key: &[u8],
        data: &[u8],
        next_monitor: u64,
    ) -> Result<(), LogStoreError>;
}

impl<T: SimplifiedLogStore + ?Sized> LogStore for T {
    fn get_last_tree_head(&self) -> Result<Option<(TreeHead, [u8; 32])>, LogStoreError> {
        self.get_raw_tree_head()?
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

    fn set_last_tree_head(&mut self, head: TreeHead, root: [u8; 32]) -> Result<(), LogStoreError> {
        let raw = wire::StoredTreeHead {
            tree_head: Some(head),
            root: root.to_vec(),
        }
        .encode_to_vec();
        self.set_raw_tree_head(&raw)
    }

    fn get_data(&self, key: &[u8]) -> Result<Option<MonitoringData>, LogStoreError> {
        self.get_raw_data(key)?
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

    fn set_data(&mut self, key: &[u8], data: MonitoringData) -> Result<(), LogStoreError> {
        let next_monitor = data.next_monitor();
        let raw = wire::StoredMonitoringData {
            index: data.index.to_vec(),
            pos: data.pos,
            ptrs: data.ptrs,
            owned: data.owned,
        }
        .encode_to_vec();
        self.set_raw_data(key, &raw, next_monitor)
    }
}
