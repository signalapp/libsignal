//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![cfg_attr(not(test), warn(clippy::unwrap_used))]

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
use std::time::SystemTime;

pub use ed25519_dalek::VerifyingKey;
pub use verify::Error;
use verify::{
    truncate_search_response, verify_distinguished, verify_monitor, verify_search, verify_update,
};
pub use vrf::PublicKey as VrfPublicKey;
pub use wire::{
    ChatDistinguishedResponse, ChatSearchResponse, CondensedTreeSearchResponse, FullTreeHead,
    MonitorRequest, MonitorResponse, SearchRequest, SearchResponse, StoredMonitoringData,
    StoredTreeHead, TreeHead, UpdateRequest, UpdateResponse,
};

/// DeploymentMode specifies the way that a transparency log is deployed.
#[derive(PartialEq, Clone, Copy)]
pub enum DeploymentMode {
    ContactMonitoring,
    ThirdPartyManagement(VerifyingKey),
    ThirdPartyAuditing(VerifyingKey),
}

impl DeploymentMode {
    fn byte(&self) -> u8 {
        match self {
            DeploymentMode::ContactMonitoring => 1,
            DeploymentMode::ThirdPartyManagement(_) => 2,
            DeploymentMode::ThirdPartyAuditing(_) => 3,
        }
    }

    fn get_associated_key(&self) -> Option<&VerifyingKey> {
        match self {
            DeploymentMode::ContactMonitoring => None,
            DeploymentMode::ThirdPartyManagement(key) => Some(key),
            DeploymentMode::ThirdPartyAuditing(key) => Some(key),
        }
    }
}

pub type TreeRoot = [u8; 32];
pub type LastTreeHead = (TreeHead, TreeRoot);

impl StoredTreeHead {
    pub fn into_last_tree_head(self) -> Option<LastTreeHead> {
        let StoredTreeHead { tree_head, root } = self;
        Some((tree_head?, root.try_into().ok()?))
    }
}

impl From<LastTreeHead> for StoredTreeHead {
    fn from((tree_head, root): LastTreeHead) -> Self {
        Self {
            tree_head: Some(tree_head),
            root: root.into(),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct SearchContext {
    pub last_tree_head: Option<LastTreeHead>,
    pub data: Option<MonitoringData>,
}

#[derive(Default, Debug)]
pub struct MonitorContext {
    last_tree_head: Option<LastTreeHead>,
    data: HashMap<Vec<u8>, MonitoringData>,
}

#[derive(Clone, Debug)]
pub struct VerifiedSearchResult {
    pub value: Option<Vec<u8>>,
    pub state_update: LocalStateUpdate,
}

/// A collection of updates needed to be performed on a local state following
/// the verification of a key transparency operation.
///
/// The data field may be empty if no local data needs updating.
#[derive(Clone, Debug)]
pub struct LocalStateUpdate {
    pub tree_head: TreeHead,
    pub tree_root: TreeRoot,
    pub monitors: Vec<(Vec<u8>, MonitoringData)>,
}

impl LocalStateUpdate {
    /// Merges two updates by accumulating monitors and picking the most recent tree head.
    pub fn merge(&mut self, other: &LocalStateUpdate) {
        let LocalStateUpdate {
            tree_head,
            tree_root,
            monitors,
        } = other;

        // Only updates with the same tree head and root are merge-able
        assert_eq!(self.tree_head.timestamp, tree_head.timestamp);
        assert_eq!(tree_root, &other.tree_root);
        self.monitors.extend_from_slice(monitors);
    }
}

/// PublicConfig wraps the cryptographic keys needed to interact with a
/// transparency tree.
#[derive(Clone)]
pub struct PublicConfig {
    pub mode: DeploymentMode,
    pub signature_key: VerifyingKey,
    pub vrf_key: vrf::PublicKey,
}

/// Search request trimmed to only the parts needed for verification.
#[derive(Clone)]
pub struct SlimSearchRequest {
    pub search_key: Vec<u8>,
    pub version: Option<u32>,
}

impl SlimSearchRequest {
    pub fn new(search_key: Vec<u8>) -> Self {
        Self {
            search_key,
            version: None,
        }
    }
}

impl From<SearchRequest> for SlimSearchRequest {
    fn from(request: SearchRequest) -> Self {
        let SearchRequest {
            search_key,
            version,
            ..
        } = request;
        Self {
            search_key,
            version,
        }
    }
}

/// Key transparency main API entrypoint
pub struct KeyTransparency {
    /// Key transparency system configuration
    pub config: PublicConfig,
}

impl KeyTransparency {
    /// Checks that the output of a Search operation is valid and updates the
    /// client's stored data. `res.value.value` may only be consumed by the
    /// application if this function returns successfully.
    pub fn verify_search(
        &self,
        request: SlimSearchRequest,
        response: SearchResponse,
        context: SearchContext,
        force_monitor: bool,
        now: SystemTime,
    ) -> Result<VerifiedSearchResult, verify::Error> {
        let unverified_value = response.value.as_ref().map(|v| v.value.clone());
        let state_update =
            verify_search(&self.config, request, response, context, force_monitor, now)?;
        Ok(VerifiedSearchResult {
            // the value has now been verified
            value: unverified_value,
            state_update,
        })
    }

    /// Checks that the provided FullTreeHead has a valid consistency proof relative
    /// to the provided distinguished head.
    pub fn verify_distinguished(
        &self,
        full_tree_head: &FullTreeHead,
        distinguished_size: u64,
        distinguished_root: [u8; 32],
        last_tree_head: Option<LastTreeHead>,
    ) -> Result<(), verify::Error> {
        verify_distinguished(
            full_tree_head,
            distinguished_size,
            distinguished_root,
            last_tree_head,
        )
    }

    /// Returns the TreeHead that would've been issued immediately after the value
    /// being searched for in `SearchResponse` was sequenced.
    ///
    /// Most validation is skipped so the SearchResponse MUST already be verified.
    pub fn truncate_search_response(
        &self,
        request: &SearchRequest,
        response: &SearchResponse,
    ) -> Result<(u64, [u8; 32]), verify::Error> {
        truncate_search_response(&self.config, request, response)
    }

    /// Checks that the output of a Monitor operation is valid and updates the
    /// client's stored data.
    pub fn verify_monitor<'a>(
        &'a self,
        request: &'a MonitorRequest,
        response: &'a MonitorResponse,
        context: MonitorContext,
        now: SystemTime,
    ) -> Result<LocalStateUpdate, verify::Error> {
        verify_monitor(&self.config, request, response, context, now)
    }

    /// Checks that the output of an Update operation is valid and updates the
    /// client's stored data.
    pub fn verify_update(
        &self,
        request: &UpdateRequest,
        response: &UpdateResponse,
        context: SearchContext,
        now: SystemTime,
    ) -> Result<LocalStateUpdate, verify::Error> {
        verify_update(&self.config, request, response, context, now)
    }
}

/// MonitoringData is the structure retained for each key in the KT server being
/// monitored.
#[derive(Debug, Eq, PartialEq, Clone)]
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

impl From<MonitoringData> for StoredMonitoringData {
    fn from(value: MonitoringData) -> Self {
        Self {
            index: value.index.into(),
            pos: value.pos,
            ptrs: value.ptrs,
            owned: value.owned,
        }
    }
}

impl From<StoredMonitoringData> for MonitoringData {
    fn from(value: StoredMonitoringData) -> Self {
        Self {
            index: value.index.try_into().expect("must me the right size"),
            pos: value.pos,
            ptrs: value.ptrs,
            owned: value.owned,
        }
    }
}
