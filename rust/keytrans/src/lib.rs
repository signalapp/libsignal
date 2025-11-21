//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]

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
use itertools::Itertools;
pub use proto::{
    ChatMonitorResponse, CondensedTreeSearchResponse,
    DistinguishedResponse as ChatDistinguishedResponse, FullAuditorTreeHead, FullTreeHead,
    MonitorKey, MonitorProof, MonitorRequest, MonitorResponse,
    SearchResponse as ChatSearchResponse, Signature, StoredAccountData, StoredMonitoringData,
    StoredTreeHead, TreeHead, UpdateRequest, UpdateResponse,
};
pub use verify::Error;
use verify::{verify_distinguished, verify_monitor, verify_search};
pub use vrf::PublicKey as VrfPublicKey;

use crate::proto::AuditorTreeHead;

#[derive(PartialEq, Clone)]
pub struct VerifyingKeys(Vec<VerifyingKey>);

impl VerifyingKeys {
    const fn empty() -> Self {
        Self(vec![])
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &VerifyingKey> {
        self.0.iter()
    }
}

impl<Keys: IntoIterator<Item = VerifyingKey>> From<Keys> for VerifyingKeys {
    fn from(keys: Keys) -> Self {
        Self(keys.into_iter().collect())
    }
}

static EMPTY_KEYS: &VerifyingKeys = &VerifyingKeys::empty();

/// DeploymentMode specifies the way that a transparency log is deployed.
#[derive(PartialEq, Clone)]
pub enum DeploymentMode {
    ContactMonitoring,
    ThirdPartyManagement(VerifyingKeys),
    ThirdPartyAuditing(VerifyingKeys),
}

impl DeploymentMode {
    fn byte(&self) -> u8 {
        match self {
            DeploymentMode::ContactMonitoring => 1,
            DeploymentMode::ThirdPartyManagement(_) => 2,
            DeploymentMode::ThirdPartyAuditing(_) => 3,
        }
    }

    fn has_associated_keys(&self) -> bool {
        match self {
            DeploymentMode::ContactMonitoring => false,
            DeploymentMode::ThirdPartyManagement(_) | DeploymentMode::ThirdPartyAuditing(_) => true,
        }
    }

    fn get_associated_keys(&self) -> &VerifyingKeys {
        match self {
            DeploymentMode::ContactMonitoring => EMPTY_KEYS,
            DeploymentMode::ThirdPartyManagement(keys)
            | DeploymentMode::ThirdPartyAuditing(keys) => keys,
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

#[derive(Default, Clone)]
pub struct Versioned<T> {
    pub item: T,
    pub version: Option<u32>,
}

impl<T> From<T> for Versioned<T> {
    fn from(item: T) -> Self {
        Self {
            item,
            version: None,
        }
    }
}

impl<T> Versioned<T> {
    pub fn new(item: T, version: u32) -> Self {
        Self {
            item,
            version: Some(version),
        }
    }

    pub fn as_ref(&self) -> Versioned<&T> {
        Versioned {
            item: &self.item,
            version: self.version,
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Versioned<U> {
        let Versioned { item, version } = self;
        Versioned {
            item: f(item),
            version,
        }
    }

    pub fn into_inner(self) -> T {
        self.item
    }
}

impl<T: Clone> Versioned<&T> {
    pub fn cloned(self) -> Versioned<T> {
        let Self { item, version } = self;
        Versioned {
            item: item.clone(),
            version,
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
#[derive(Clone)]
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
        let verified_value = unverified_value.ok_or(Error::RequiredFieldMissing("update value"))?;
        Ok(VerifiedSearchResult {
            value: verified_value,
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

/// Wraps a regular TreeHead, but guarantees there is exactly one value in its signatures field.
#[derive(Debug, Clone)]
struct SingleSignatureTreeHead(TreeHead);

trait VerifiableTreeHead {
    fn tree_size(&self) -> u64;
    fn timestamp(&self) -> i64;
    fn signature_bytes(&self) -> &[u8];

    fn to_signable_header(
        &self,
        root: &[u8; 32],
        config: &PublicConfig,
        maybe_auditor_key: Option<&VerifyingKey>,
    ) -> Vec<u8> {
        fn serialize_key(buffer: &mut Vec<u8>, key_material: &[u8], key_kind: &str) {
            let key_len = u16::try_from(key_material.len())
                .unwrap_or_else(|_| panic!("{} {}", key_kind, "key is too long to be encoded"));
            buffer.extend_from_slice(&key_len.to_be_bytes());
            buffer.extend_from_slice(key_material);
        }

        let mut buf = vec![];

        buf.extend_from_slice(&[0, 0]); // Ciphersuite
        buf.push(config.mode.byte()); // Deployment mode

        serialize_key(&mut buf, config.signature_key.as_bytes(), "signature");
        serialize_key(&mut buf, config.vrf_key.as_bytes(), "VRF");

        // If config only had a single auditor key, we could have just used that.
        // But as there can be many we should at least avoid a silly mistake of not
        // passing an auditor key if the mode requires it.
        debug_assert_eq!(
            maybe_auditor_key.is_some(),
            config.mode.has_associated_keys()
        );

        if let Some(key) = maybe_auditor_key {
            debug_assert!(
                config.mode.get_associated_keys().iter().contains(key),
                "unknown auditor key"
            );
            serialize_key(&mut buf, key.as_bytes(), "third party signature")
        }

        buf.extend_from_slice(&self.tree_size().to_be_bytes()); // Tree size
        buf.extend_from_slice(&self.timestamp().to_be_bytes()); // Timestamp
        buf.extend_from_slice(root); // Root hash

        buf
    }
}

impl VerifiableTreeHead for SingleSignatureTreeHead {
    fn tree_size(&self) -> u64 {
        self.0.tree_size
    }

    fn timestamp(&self) -> i64 {
        self.0.timestamp
    }

    fn signature_bytes(&self) -> &[u8] {
        &self
            .0
            .signatures
            .first()
            .expect("guaranteed by construction")
            .signature
    }
}

impl VerifiableTreeHead for AuditorTreeHead {
    fn tree_size(&self) -> u64 {
        self.tree_size
    }

    fn timestamp(&self) -> i64 {
        self.timestamp
    }

    fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }
}

impl TreeHead {
    /// Takes a tree head with multiple signatures and turns it into a vector of
    /// more conventional single-signature tree head.
    ///
    /// The matching is based on the auditor public keys available from the
    /// config. Note that it is _not_ signed by an auditor, it is signed by the
    /// server but auditor's public key is part of the data being signed (see
    /// `libsignal_keytrans::verify::marshal_tree_head_tbs`).
    ///
    /// Not all key transparency deployment modes have associated auditor keys,
    /// and it is possible that the source tree head will not contain all the
    /// matching signatures. In both cases the function will return `None`,
    /// deciding whether to treat it an error or not is left to the caller.
    fn to_single_signature_tree_heads<'a, 'b: 'a>(
        &'a self,
        config: &'b PublicConfig,
    ) -> Option<Vec<(&'a VerifyingKey, SingleSignatureTreeHead)>> {
        let TreeHead {
            tree_size,
            timestamp,
            signatures,
        } = self;

        // We expect to have signatures for all the auditor keys that we are configured with.
        find_matching(
            config.mode.get_associated_keys().iter(),
            signatures.iter(),
            |key, sig| key.as_bytes().as_slice() == sig.auditor_public_key.as_slice(),
            |key, sig| {
                let head = SingleSignatureTreeHead(TreeHead {
                    tree_size: *tree_size,
                    timestamp: *timestamp,
                    signatures: vec![(*sig).clone()],
                });
                (key, head)
            },
        )
    }
}

impl FullTreeHead {
    pub fn select_auditor_tree_head(
        &self,
        public_key: &VerifyingKey,
    ) -> Option<&FullAuditorTreeHead> {
        self.full_auditor_tree_heads
            .iter()
            .find(|full_head| full_head.public_key.as_slice() == public_key.as_bytes().as_slice())
    }

    pub fn auditor_tree_heads<'a>(
        &'a self,
        keys: impl ExactSizeIterator<Item = &'a VerifyingKey>,
    ) -> Option<Vec<(&'a VerifyingKey, &'a FullAuditorTreeHead)>> {
        find_matching(
            keys,
            self.full_auditor_tree_heads.iter(),
            |key, head| head.public_key.as_slice() == key.as_bytes().as_slice(),
            |key, head| (key, head),
        )
    }
}

/// Matches elements from `xs` to `ys` using an equality predicate and projects
/// each match into a result.
///
/// This function attempts to find a corresponding element in `ys` for every
/// element in `xs` by applying the equality predicate `eq`, and when a match is
/// found, applies the `project` function to create the result. The matching is
/// performed in O(n*m) time by cloning and iterating through `ys` for each
/// element in `xs`, which is acceptable for small collections. Returns `None`
/// if any element from `xs` cannot be matched to an element in `ys`, otherwise
/// returns `Some` containing a vector of all projected pairs in the order they
/// appeared in `xs`.
fn find_matching<'a, 'b, A: 'a, B: 'b, C>(
    xs: impl ExactSizeIterator<Item = &'a A>,
    ys: impl Iterator<Item = &'b B> + Clone,
    eq: impl Fn(&'a A, &'b B) -> bool,
    project: impl Fn(&'a A, &'b B) -> C,
) -> Option<Vec<C>> {
    debug_assert!(xs.len() <= 10, "quadratic algorithm is being used");
    let mut result = Vec::with_capacity(xs.len());
    for x in xs {
        // Yes, this is O(n*m), but our n and m are both 3 at the time of this writing.
        if let Some(y) = ys.clone().find(|y| eq(x, *y)) {
            result.push(project(x, y));
        } else {
            return None;
        }
    }
    Some(result)
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;

    #[test_case(&[1, 2, 3], &[10, 20, 30] => Some(vec![11, 22, 33]); "perfect match")]
    #[test_case(&[1, 2, 3], &[10, 20, 30, 40] => Some(vec![11, 22, 33]); "extra ys")]
    #[test_case(&[1], &[] => None; "no match")]
    #[test_case(&[], &[] => Some(vec![]); "empty")]
    fn find_matching_works(xs: &[i32], ys: &[i32]) -> Option<Vec<i32>> {
        find_matching(xs.iter(), ys.iter(), |a, b| a * 10 == *b, |a, b| a + b)
    }
}
