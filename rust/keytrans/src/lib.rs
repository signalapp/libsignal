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
mod proto;
mod verify;
mod vrf;

use std::collections::HashMap;
use std::time::SystemTime;

pub use ed25519_dalek::VerifyingKey;
pub use proto::{
    ChatMonitorResponse, CondensedTreeSearchResponse,
    DistinguishedResponse as ChatDistinguishedResponse, FullTreeHead, MonitorKey, MonitorProof,
    MonitorRequest, MonitorResponse, SearchResponse as ChatSearchResponse, StoredAccountData,
    StoredMonitoringData, StoredTreeHead, TreeHead, UpdateRequest, UpdateResponse,
};
pub use verify::Error;
use verify::{
    truncate_search_response, verify_distinguished, verify_monitor, verify_search, verify_update,
};
pub use vrf::PublicKey as VrfPublicKey;

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
pub struct SearchContext<'a> {
    pub last_tree_head: Option<&'a LastTreeHead>,
    pub last_distinguished_tree_head: Option<&'a LastTreeHead>,
    pub data: Option<MonitoringData>,
}

#[derive(Debug)]
pub struct MonitorContext<'a> {
    pub last_tree_head: Option<&'a LastTreeHead>,
    pub last_distinguished_tree_head: &'a LastTreeHead,
    pub data: HashMap<Vec<u8>, MonitoringData>,
}

#[derive(Clone, Debug)]
pub struct VerifiedSearchResult {
    pub value: Vec<u8>,
    pub state_update: SearchStateUpdate,
}

impl VerifiedSearchResult {
    pub fn tree_root(&self) -> &TreeRoot {
        &self.state_update.tree_root
    }

    pub fn are_all_roots_equal<'b>(
        &self,
        tail: impl IntoIterator<Item = Option<&'b Self>>,
    ) -> bool {
        let mut all_roots_are_equal = true;
        for other in tail.into_iter().flatten() {
            all_roots_are_equal &= self.tree_root() == other.tree_root();
        }
        all_roots_are_equal
    }
}

/// A collection of updates needed to be performed on a local state following
/// the verification of a key transparency operation.
///
/// The data field may be empty if no local data needs updating.
#[derive(Clone, Debug)]
pub struct LocalStateUpdate<T> {
    pub tree_head: TreeHead,
    pub tree_root: TreeRoot,
    pub monitoring_data: T,
}

pub type SearchStateUpdate = LocalStateUpdate<Option<MonitoringData>>;
pub type MonitorStateUpdate = LocalStateUpdate<HashMap<Vec<u8>, MonitoringData>>;

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

/// Self-sufficient key transparency search response.
///
/// In order to produce a consistent result chat server returns three [`CondensedTreeSearchResponse`]
/// with a single [`FullTreeHead`], however each such response is individually verifiable. This type
/// re-creates the original self-sufficient search response.
#[derive(Clone, Debug)]
pub struct FullSearchResponse<'a> {
    pub condensed: CondensedTreeSearchResponse,
    pub tree_head: &'a FullTreeHead,
}

impl<'a> FullSearchResponse<'a> {
    pub fn new(condensed: CondensedTreeSearchResponse, tree_head: &'a FullTreeHead) -> Self {
        Self {
            condensed,
            tree_head,
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
        response: FullSearchResponse,
        context: SearchContext,
        force_monitor: bool,
        now: SystemTime,
    ) -> Result<VerifiedSearchResult, verify::Error> {
        let unverified_value = response.condensed.value.as_ref().map(|v| v.value.clone());
        let state_update =
            verify_search(&self.config, request, response, context, force_monitor, now)?;
        Ok(VerifiedSearchResult {
            // the value has now been verified
            value: unverified_value.ok_or(Error::VerificationFailed(
                "unverified_value is not set".to_string(),
            ))?,
            state_update,
        })
    }

    /// Checks that the provided FullTreeHead has a valid consistency proof relative
    /// to the provided distinguished head.
    pub fn verify_distinguished(
        &self,
        full_tree_head: &FullTreeHead,
        last_tree_head: Option<&LastTreeHead>,
        last_distinguished_tree_head: &LastTreeHead,
    ) -> Result<(), verify::Error> {
        verify_distinguished(full_tree_head, last_tree_head, last_distinguished_tree_head)
    }

    /// Returns the TreeHead that would've been issued immediately after the value
    /// being searched for in `SearchResponse` was sequenced.
    ///
    /// Most validation is skipped so the SearchResponse MUST already be verified.
    pub fn truncate_search_response(
        &self,
        request: &SlimSearchRequest,
        response: &FullSearchResponse,
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
    ) -> Result<MonitorStateUpdate, verify::Error> {
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
    ) -> Result<SearchStateUpdate, verify::Error> {
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

    /// The largest known log position for the given search key.
    pub fn latest_log_position(&self) -> u64 {
        self.ptrs
            .keys()
            .max()
            .copied()
            .expect("at least one version must be present")
    }

    /// The greatest known version of the search key.
    pub fn greatest_version(&self) -> u32 {
        self.ptrs
            .values()
            .max()
            .copied()
            .expect("at least one version must be present")
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

/// An in-memory representation of the [`StoredAccountData`] with correct optionality of the fields
#[derive(Debug, Clone, PartialEq)]
pub struct AccountData {
    pub aci: MonitoringData,
    pub e164: Option<MonitoringData>,
    pub username_hash: Option<MonitoringData>,
    pub last_tree_head: LastTreeHead,
}

impl TryFrom<StoredAccountData> for AccountData {
    type Error = Error;

    fn try_from(stored: StoredAccountData) -> Result<Self, Self::Error> {
        let StoredAccountData {
            aci,
            e164,
            username_hash,
            last_tree_head,
        } = stored;
        let last_tree_head = last_tree_head.ok_or(Error::RequiredFieldMissing("last_tree_head"))?;
        Ok(Self {
            aci: aci
                .map(MonitoringData::from)
                .ok_or(Error::RequiredFieldMissing("aci"))?,
            e164: e164.map(MonitoringData::from),
            username_hash: username_hash.map(MonitoringData::from),
            last_tree_head: last_tree_head
                .into_last_tree_head()
                .expect("valid tree head"),
        })
    }
}

impl From<AccountData> for StoredAccountData {
    fn from(acc: AccountData) -> Self {
        let AccountData {
            aci,
            e164,
            username_hash,
            last_tree_head,
        } = acc;
        Self {
            aci: Some(aci.into()),
            e164: e164.map(StoredMonitoringData::from),
            username_hash: username_hash.map(StoredMonitoringData::from),
            last_tree_head: Some(last_tree_head.into()),
        }
    }
}
