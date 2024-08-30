//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::commitments::verify as verify_commitment;
use crate::guide::{InvalidState, ProofGuide};
use crate::implicit::{full_monitoring_path, monitoring_path};
use crate::log::{evaluate_batch_proof, truncate_batch_proof, verify_consistency_proof};
use crate::prefix::{evaluate as evaluate_prefix, MalformedProof};
use crate::store::{LogStore, LogStoreError};
use crate::wire::*;
use crate::{guide, log, vrf, DeploymentMode, MonitoringData, PublicConfig};

/// The range of allowed timestamp values relative to "now".
/// The timestamps will have to be in [now - max_behind .. now + max_ahead]
const ALLOWED_TIMESTAMP_RANGE: &TimestampRange = &TimestampRange {
    max_behind: Duration::from_secs(24 * 60 * 60),
    max_ahead: Duration::from_secs(10),
};

/// The range of allowed timestamp values relative to "now" used for auditor.
const ALLOWED_AUDITOR_TIMESTAMP_RANGE: &TimestampRange = &TimestampRange {
    max_behind: Duration::from_secs(7 * 24 * 60 * 60),
    max_ahead: Duration::from_secs(10),
};
const ENTRIES_MAX_BEHIND: u64 = 10_000_000;

#[derive(Debug, displaydoc::Display)]
pub enum Error {
    /// Required field not found
    RequiredFieldMissing,
    /// Proof element is wrong size
    InvalidProofElement,
    /// Value is too long to be encoded
    ValueTooLong,
    /// Verification failed: {0}
    VerificationFailed(String),
    /// Storage operation failed: {0}
    StorageFailure(String),
}

impl From<log::Error> for Error {
    fn from(err: log::Error) -> Self {
        Self::VerificationFailed(err.to_string())
    }
}

impl From<vrf::Error> for Error {
    fn from(err: vrf::Error) -> Self {
        Self::VerificationFailed(err.to_string())
    }
}

impl From<guide::InvalidState> for Error {
    fn from(err: InvalidState) -> Self {
        Self::VerificationFailed(err.to_string())
    }
}

impl From<MalformedProof> for Error {
    fn from(err: MalformedProof) -> Self {
        Self::VerificationFailed(err.to_string())
    }
}

impl From<LogStoreError> for Error {
    fn from(err: LogStoreError) -> Self {
        Self::StorageFailure(err.to_string())
    }
}

type Result<T> = std::result::Result<T, Error>;

fn get_proto_field<T>(field: &Option<T>) -> Result<&T> {
    field.as_ref().ok_or(Error::RequiredFieldMissing)
}

fn get_hash_proof(proof: &[Vec<u8>]) -> Result<Vec<[u8; 32]>> {
    proof
        .iter()
        .map(|elem| <&[u8] as TryInto<[u8; 32]>>::try_into(elem))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| Error::InvalidProofElement)
}

fn serialize_key(buffer: &mut Vec<u8>, key_material: &[u8], key_kind: &str) {
    let key_len = u16::try_from(key_material.len())
        .unwrap_or_else(|_| panic!("{} {}", key_kind, "key is too long to be encoded"));
    buffer.extend_from_slice(&key_len.to_be_bytes());
    buffer.extend_from_slice(key_material);
}

fn marshal_tree_head_tbs(
    tree_size: u64,
    timestamp: i64,
    root: &[u8; 32],
    config: &PublicConfig,
) -> Result<Vec<u8>> {
    let mut buf = vec![];

    buf.extend_from_slice(&[0, 0]); // Ciphersuite
    buf.push(config.mode.byte()); // Deployment mode

    serialize_key(&mut buf, config.signature_key.as_bytes(), "signature");
    serialize_key(&mut buf, config.vrf_key.as_bytes(), "VRF");

    if let Some(key) = config.mode.get_associated_key() {
        serialize_key(&mut buf, key.as_bytes(), "third party signature")
    }

    buf.extend_from_slice(&tree_size.to_be_bytes()); // Tree size
    buf.extend_from_slice(&timestamp.to_be_bytes()); // Timestamp
    buf.extend_from_slice(root); // Root hash

    Ok(buf)
}

fn marshal_update_value(value: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![];

    let length = u32::try_from(value.len()).map_err(|_| Error::ValueTooLong)?;
    buf.extend_from_slice(&length.to_be_bytes());
    buf.extend_from_slice(value);

    Ok(buf)
}

/// Returns the hash of the leaf of the transparency tree.
fn leaf_hash(prefix_root: &[u8; 32], commitment: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prefix_root);
    hasher.update(commitment);

    hasher.finalize().into()
}

/// Checks the signature on the provided transparency tree head using the given key
fn verify_tree_head_signature(
    config: &PublicConfig,
    head: &TreeHead,
    root: &[u8; 32],
    verifying_key: &VerifyingKey,
) -> Result<()> {
    let raw = marshal_tree_head_tbs(head.tree_size, head.timestamp, root, config)?;
    let sig = Signature::from_slice(&head.signature).map_err(|_| {
        Error::VerificationFailed("failed to verify tree head signature".to_string())
    })?;
    verifying_key
        .verify(&raw, &sig)
        .map_err(|_| Error::VerificationFailed("failed to verify tree head signature".to_string()))
}

/// Checks that a FullTreeHead structure is valid. It stores the tree head for
/// later requests if it succeeds.
fn verify_full_tree_head(
    config: &PublicConfig,
    storage: &mut dyn LogStore,
    fth: &FullTreeHead,
    root: [u8; 32],
    now: SystemTime,
) -> Result<()> {
    let tree_head = get_proto_field(&fth.tree_head)?.clone();

    // 1. Verify the proof in FullTreeHead.consistency, if one is expected.
    // 3. Verify that the timestamp and tree_size fields of the TreeHead are
    //    greater than or equal to what they were before.
    match storage.get_last_tree_head()? {
        None => {
            if !fth.last.is_empty() {
                return Err(Error::VerificationFailed(
                    "consistency proof provided when not expected".to_string(),
                ));
            }
        }
        Some((last, last_root)) if last.tree_size == tree_head.tree_size => {
            if root != last_root {
                return Err(Error::VerificationFailed(
                    "root is different but tree size is same".to_string(),
                ));
            }
            if tree_head.timestamp < last.timestamp {
                return Err(Error::VerificationFailed(
                    "current timestamp is less than previous timestamp".to_string(),
                ));
            }
            if !fth.last.is_empty() {
                return Err(Error::VerificationFailed(
                    "consistency proof provided when not expected".to_string(),
                ));
            }
        }
        Some((last, last_root)) => {
            if tree_head.tree_size < last.tree_size {
                return Err(Error::VerificationFailed(
                    "current tree size is less than previous tree size".to_string(),
                ));
            }
            if tree_head.timestamp < last.timestamp {
                return Err(Error::VerificationFailed(
                    "current timestamp is less than previous timestamp".to_string(),
                ));
            }
            let proof = get_hash_proof(&fth.last)?;
            verify_consistency_proof(last.tree_size, tree_head.tree_size, &proof, last_root, root)?
        }
    };

    // 2. Verify the signature in TreeHead.signature.
    verify_tree_head_signature(config, &tree_head, &root, &config.signature_key)?;

    // 3. Verify that the timestamp in TreeHead is sufficiently recent.
    verify_timestamp(tree_head.timestamp, ALLOWED_TIMESTAMP_RANGE, None, now)?;

    // 4. If third-party auditing is used, verify auditor_tree_head with the
    //    steps described in Section 11.2.
    if let DeploymentMode::ThirdPartyAuditing(auditor_key) = config.mode {
        let auditor_tree_head = get_proto_field(&fth.auditor_tree_head)?;
        let auditor_head = get_proto_field(&auditor_tree_head.tree_head)?;

        // 2. Verify that TreeHead.timestamp is sufficiently recent.
        verify_timestamp(
            auditor_head.timestamp,
            ALLOWED_AUDITOR_TIMESTAMP_RANGE,
            Some("auditor"),
            now,
        )?;

        // 3. Verify that TreeHead.tree_size is sufficiently close to the most
        //    recent tree head from the service operator.
        if auditor_head.tree_size > tree_head.tree_size {
            return Err(Error::VerificationFailed(
                "auditor tree head may not be further along than service tree head".to_string(),
            ));
        }
        if tree_head.tree_size - auditor_head.tree_size > ENTRIES_MAX_BEHIND {
            return Err(Error::VerificationFailed(
                "auditor tree head is too far behind service tree head".to_string(),
            ));
        }
        // 4. Verify the consistency proof between this tree head and the most
        //    recent tree head from the service operator.
        // 1. Verify the signature in TreeHead.signature.
        if tree_head.tree_size > auditor_head.tree_size {
            let auditor_root: &[u8; 32] = get_proto_field(&auditor_tree_head.root_value)?
                .as_slice()
                .try_into()
                .map_err(|_| {
                    Error::VerificationFailed("auditor tree head is malformed".to_string())
                })?;
            let proof = get_hash_proof(&auditor_tree_head.consistency)?;
            verify_consistency_proof(
                auditor_head.tree_size,
                tree_head.tree_size,
                &proof,
                *auditor_root,
                root,
            )?;
            verify_tree_head_signature(config, auditor_head, auditor_root, &auditor_key)?;
        } else {
            if !auditor_tree_head.consistency.is_empty() {
                return Err(Error::VerificationFailed(
                    "consistency proof provided when not expected".to_string(),
                ));
            }
            if auditor_tree_head.root_value.is_some() {
                return Err(Error::VerificationFailed(
                    "explicit root value provided when not expected".to_string(),
                ));
            }
            verify_tree_head_signature(config, auditor_head, &root, &auditor_key)?;
        }
    }

    Ok(storage.set_last_tree_head(tree_head, root)?)
}

/// The range of allowed timestamp values relative to "now".
/// The timestamps will have to be in [now - max_behind .. now + max_ahead]
struct TimestampRange {
    max_behind: Duration,
    max_ahead: Duration,
}

fn verify_timestamp(
    timestamp: i64,
    allowed_range: &TimestampRange,
    description: Option<&str>,
    now: SystemTime,
) -> Result<()> {
    let TimestampRange {
        max_behind,
        max_ahead,
    } = allowed_range;
    let now = now
        .duration_since(UNIX_EPOCH)
        .expect("valid system time")
        .as_millis() as i128;
    let delta = now - timestamp as i128;
    let format_message = |s: &str| match description {
        None => s.to_string(),
        Some(desc) => format!("{} {}", desc, s),
    };
    if delta > max_behind.as_millis() as i128 {
        let message = format_message("timestamp is too far behind current time");
        return Err(Error::VerificationFailed(message));
    }
    if (-delta) > max_ahead.as_millis() as i128 {
        let message = format_message("timestamp is too far ahead of current time");
        return Err(Error::VerificationFailed(message));
    }
    Ok(())
}

/// Checks that the provided FullTreeHead has a valid consistency proof relative
/// to the provided distinguished head.
pub fn verify_distinguished(
    storage: &mut dyn LogStore,
    fth: &FullTreeHead,
    distinguished_size: u64,
    distinguished_root: [u8; 32],
) -> Result<()> {
    let tree_size = get_proto_field(&fth.tree_head)?.tree_size;

    let root = match storage.get_last_tree_head()? {
        Some((tree_head, root)) if tree_head.tree_size == tree_size => root,
        _ => {
            return Err(Error::VerificationFailed(
                "expected tree head not found in storage".to_string(),
            ))
        }
    };

    // Handle special case when tree_size == distinguished_size.
    if tree_size == distinguished_size {
        let result = if root == distinguished_root {
            Ok(())
        } else {
            Err(Error::VerificationFailed(
                "root hash does not match expected value".to_string(),
            ))
        };
        return result;
    }

    Ok(verify_consistency_proof(
        distinguished_size,
        tree_size,
        &get_hash_proof(&fth.distinguished)?,
        distinguished_root,
        root,
    )?)
}

fn evaluate_vrf_proof(
    proof: &[u8],
    vrf_key: &vrf::PublicKey,
    search_key: &[u8],
) -> Result<[u8; 32]> {
    let proof = proof.try_into().map_err(|_| MalformedProof)?;
    Ok(vrf_key.proof_to_hash(search_key, proof)?)
}

/// The shared implementation of verify_search and verify_update.
fn verify_search_internal(
    config: &PublicConfig,
    storage: &mut dyn LogStore,
    req: &SearchRequest,
    res: &SearchResponse,
    monitor: bool,
    now: SystemTime,
) -> Result<()> {
    // NOTE: Update this function in tandem with truncate_search_response.

    let index = evaluate_vrf_proof(&res.vrf_proof, &config.vrf_key, &req.search_key)?;

    // Evaluate the search proof.
    let full_tree_head = get_proto_field(&res.tree_head)?;
    let tree_size = {
        let tree_head = get_proto_field(&full_tree_head.tree_head)?;
        tree_head.tree_size
    };
    let search_proof = get_proto_field(&res.search)?;

    let guide = ProofGuide::new(req.version, search_proof.pos, tree_size);

    let mut i = 0;
    let mut leaves = HashMap::new();
    let mut steps = HashMap::new();
    let result = guide.consume(|guide, next_id| {
        if i >= search_proof.steps.len() {
            return Err(Error::VerificationFailed(
                "unexpected number of steps in search proof".to_string(),
            ));
        }
        let step = &search_proof.steps[i];
        let prefix_proof = get_proto_field(&step.prefix)?;
        guide.insert(next_id, prefix_proof.counter);

        // Evaluate the prefix proof and combine it with the commitment to get
        // the value stored in the log.
        let prefix_root = evaluate_prefix(&index, search_proof.pos, prefix_proof)?;
        let commitment = step
            .commitment
            .as_slice()
            .try_into()
            .map_err(|_| MalformedProof)?;
        leaves.insert(next_id, leaf_hash(&prefix_root, commitment));
        steps.insert(next_id, step.clone());

        i += 1;
        Ok::<(), Error>(())
    })?;

    if i != search_proof.steps.len() {
        return Err(Error::VerificationFailed(
            "unexpected number of steps in search proof".to_string(),
        ));
    }

    // Verify commitment opening.
    let (result_i, result_id) = result.ok_or_else(|| {
        Error::VerificationFailed("failed to find expected version of key".to_string())
    })?;
    let result_step = &search_proof.steps[result_i];

    let value = marshal_update_value(&get_proto_field(&res.value)?.value)?;
    let opening = res
        .opening
        .as_slice()
        .try_into()
        .map_err(|_| Error::VerificationFailed("malformed opening".to_string()))?;

    if !verify_commitment(&req.search_key, &result_step.commitment, &value, opening) {
        return Err(Error::VerificationFailed(
            "failed to verify commitment opening".to_string(),
        ));
    }

    // Evaluate the inclusion proof to get a candidate root value.
    let (ids, values) = into_sorted_pairs(leaves);

    let inclusion_proof = get_hash_proof(&search_proof.inclusion)?;
    let root = evaluate_batch_proof(&ids, tree_size, &values, &inclusion_proof)?;

    // Verify the tree head with the candidate root.
    verify_full_tree_head(config, storage, full_tree_head, root, now)?;

    // Update stored monitoring data.
    let size = if req.search_key == b"distinguished" {
        // Make sure we don't update monitoring data based on parts of the tree
        // that we don't intend to retain.
        result_id + 1
    } else {
        tree_size
    };
    let ver = get_proto_field(&result_step.prefix)?.counter;

    let mut mdw = MonitoringDataWrapper::load(storage, &req.search_key)?;
    if monitor || config.mode == DeploymentMode::ContactMonitoring {
        mdw.start_monitoring(&index, search_proof.pos, result_id, ver, monitor);
    }
    mdw.check_search_consistency(size, &index, search_proof.pos, result_id, ver, monitor)?;
    mdw.update(size, &steps)?;
    mdw.save(storage, &req.search_key)
}

/// Checks that the output of a Search operation is valid and updates the
/// client's stored data. `res.value.value` may only be consumed by the
/// application if this function returns successfully.
pub fn verify_search(
    config: &PublicConfig,
    storage: &mut dyn LogStore,
    req: &SearchRequest,
    res: &SearchResponse,
    force_monitor: bool,
) -> Result<()> {
    verify_search_internal(config, storage, req, res, force_monitor, SystemTime::now())
}

/// Checks that the output of an Update operation is valid and updates the
/// client's stored data.
pub fn verify_update(
    config: &PublicConfig,
    storage: &mut dyn LogStore,
    req: &UpdateRequest,
    res: &UpdateResponse,
) -> Result<()> {
    verify_search_internal(
        config,
        storage,
        &SearchRequest {
            search_key: req.search_key.clone(),
            version: None,
            consistency: req.consistency,
        },
        &SearchResponse {
            tree_head: res.tree_head.clone(),
            vrf_proof: res.vrf_proof.clone(),
            search: res.search.clone(),

            opening: res.opening.clone(),
            value: Some(UpdateValue {
                value: req.value.clone(),
            }),
        },
        true,
        SystemTime::now(),
    )
}

/// Checks that the output of a Monitor operation is valid and updates the
/// client's stored data.
pub fn verify_monitor(
    config: &PublicConfig,
    storage: &mut dyn LogStore,
    req: &MonitorRequest,
    res: &MonitorResponse,
) -> Result<()> {
    // Verify proof responses are the expected lengths.
    if req.owned_keys.len() != res.owned_proofs.len() {
        return Err(Error::VerificationFailed(
            "monitoring response is malformed: wrong number of owned key proofs".to_string(),
        ));
    }
    if req.contact_keys.len() != res.contact_proofs.len() {
        return Err(Error::VerificationFailed(
            "monitoring response is malformed: wrong number of contact key proofs".to_string(),
        ));
    }

    let full_tree_head = get_proto_field(&res.tree_head)?;
    let tree_head = get_proto_field(&full_tree_head.tree_head)?;
    let tree_size = tree_head.tree_size;

    // Process all of the individual MonitorProof structures.
    let mut mpa = MonitorProofAcc::new(tree_size);
    // TODO: futures_util::future::join_all() maybe?
    for (key, proof) in req.owned_keys.iter().zip(res.owned_proofs.iter()) {
        mpa.process(storage, key, proof)?;
    }
    for (key, proof) in req.contact_keys.iter().zip(res.contact_proofs.iter()) {
        mpa.process(storage, key, proof)?;
    }

    // Evaluate the inclusion proof to get a candidate root value.
    let inclusion_proof = get_hash_proof(&res.inclusion)?;
    let root = if mpa.leaves.is_empty() {
        match inclusion_proof[..] {
            [root] => root,
            _ => {
                return Err(Error::VerificationFailed(
                    "monitoring response is malformed: inclusion proof should be root".to_string(),
                ))
            }
        }
    } else {
        let (ids, values) = into_sorted_pairs(mpa.leaves);

        evaluate_batch_proof(&ids, tree_size, &values, &inclusion_proof)?
    };

    // Verify the tree head with the candidate root.
    verify_full_tree_head(config, storage, full_tree_head, root, SystemTime::now())?;

    // Update monitoring data.
    for (key, entry) in req
        .owned_keys
        .iter()
        .chain(req.contact_keys.iter())
        .zip(mpa.entries.iter())
    {
        let size = if key.search_key == b"distinguished" {
            // Generally an effort has been made to avoid referencing the
            // "distinguished" key in the core keytrans library, but it
            // simplifies things here:
            //
            // When working with the "distinguished" key, the last observed tree
            // head is always trimmed back to create an anonymity set. As such,
            // when monitoring the "distinguished" key, we need to make sure we
            // don't update monitoring data based on parts of the tree that we
            // don't intend to retain.
            req.consistency
                .and_then(|consistency| consistency.last)
                .ok_or(Error::VerificationFailed("monitoring request malformed: consistency field expected when monitoring distinguished key".to_string()))?
        } else {
            tree_size
        };
        let mut mdw = MonitoringDataWrapper::load(storage, &key.search_key)?;
        mdw.update(size, entry)?;
        mdw.save(storage, &key.search_key)?;
    }

    Ok(())
}

struct MonitorProofAcc {
    tree_size: u64,
    /// Map from position in the log to leaf hash.
    leaves: HashMap<u64, [u8; 32]>,
    /// For each MonitorProof struct processed, contains the map that needs to be
    /// passed to MonitoringDataWrapper::update to update monitoring data for the
    /// search key.
    entries: Vec<HashMap<u64, ProofStep>>,
}

impl MonitorProofAcc {
    fn new(tree_size: u64) -> Self {
        Self {
            tree_size,
            leaves: HashMap::new(),
            entries: vec![],
        }
    }

    fn process(
        &mut self,
        storage: &mut dyn LogStore,
        key: &MonitorKey,
        proof: &MonitorProof,
    ) -> Result<()> {
        // Get the existing monitoring data from storage and check that it
        // matches the request.
        let data = storage.get_data(&key.search_key)?.ok_or_else(|| {
            Error::VerificationFailed(
                "unable to process monitoring response for unknown search key".to_string(),
            )
        })?;

        // Compute which entry in the log each proof is supposed to correspond to.
        let entries = full_monitoring_path(&key.entries, data.pos, self.tree_size);
        if entries.len() != proof.steps.len() {
            return Err(Error::VerificationFailed(
                "monitoring response is malformed: wrong number of proof steps".to_string(),
            ));
        }

        // Evaluate each proof step to get the candidate leaf values.
        let mut steps = HashMap::new();
        for (entry, step) in entries.iter().zip(proof.steps.iter()) {
            let prefix_proof = get_proto_field(&step.prefix)?;
            let prefix_root = evaluate_prefix(&data.index, data.pos, prefix_proof)?;
            let commitment = step
                .commitment
                .as_slice()
                .try_into()
                .map_err(|_| MalformedProof)?;
            let leaf = leaf_hash(&prefix_root, commitment);

            if let Some(other) = self.leaves.get(entry) {
                if leaf != *other {
                    return Err(Error::VerificationFailed(
                        "monitoring response is malformed: multiple values for same leaf"
                            .to_string(),
                    ));
                }
            } else {
                self.leaves.insert(*entry, leaf);
            }

            steps.insert(*entry, step.clone());
        }
        self.entries.push(steps);

        Ok(())
    }
}

struct MonitoringDataWrapper {
    inner: Option<MonitoringData>,
    changed: bool,
}

impl MonitoringDataWrapper {
    fn load(storage: &mut dyn LogStore, search_key: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: storage.get_data(search_key)?,
            changed: false,
        })
    }

    /// Adds a key to the database of keys to monitor, if it's not already
    /// present.
    fn start_monitoring(
        &mut self,
        index: &[u8; 32],
        zero_pos: u64,
        ver_pos: u64,
        version: u32,
        owned: bool,
    ) {
        if self.inner.is_none() {
            self.inner = Some(MonitoringData {
                index: *index,
                pos: zero_pos,
                ptrs: HashMap::from([(ver_pos, version)]),
                owned,
            });
            self.changed = true;
        }
    }

    fn check_search_consistency(
        &mut self,
        tree_size: u64,
        index: &[u8; 32],
        zero_pos: u64,
        ver_pos: u64,
        version: u32,
        owned: bool,
    ) -> Result<()> {
        let data = match self.inner.as_mut() {
            Some(data) => data,
            None => return Ok(()),
        };

        if *index != data.index {
            return Err(Error::VerificationFailed(
                "given search key index does not match database".to_string(),
            ));
        }
        if zero_pos != data.pos {
            return Err(Error::VerificationFailed(
                "given search start position does not match database".to_string(),
            ));
        }

        match data.ptrs.get(&ver_pos) {
            Some(ver) => {
                if *ver != version {
                    return Err(Error::VerificationFailed(
                        "different versions of key recorded at same position".to_string(),
                    ));
                }
            }
            None => {
                match monitoring_path(ver_pos, zero_pos, tree_size).find_map(|x| data.ptrs.get(&x))
                {
                    Some(ver) => {
                        if *ver < version {
                            return Err(Error::VerificationFailed(
                                "prefix tree has unexpectedly low version counter".to_string(),
                            ));
                        }
                    }
                    None => {
                        data.ptrs.insert(ver_pos, version);
                        self.changed = true;
                    }
                };
            }
        }

        if !data.owned && owned {
            data.owned = true;
            self.changed = true;
        }

        Ok(())
    }

    /// Updates the internal monitoring data for a key as much as possible given
    /// a set of ProofStep structures. It should only be called after
    /// verify_full_tree_head has succeeded to ensure that we don't store updated
    /// monitoring data tied to a tree head that isn't valid.
    fn update(&mut self, tree_size: u64, entries: &HashMap<u64, ProofStep>) -> Result<()> {
        let data = match self.inner.as_mut() {
            Some(data) => data,
            None => return Ok(()),
        };

        let mut changed = false;
        let mut ptrs = HashMap::new();

        for (entry, ver) in data.ptrs.iter() {
            let mut entry = *entry;
            let mut ver = *ver;

            for x in monitoring_path(entry, data.pos, tree_size) {
                match entries.get(&x) {
                    None => break,
                    Some(step) => {
                        let ctr = get_proto_field(&step.prefix)?.counter;
                        if ctr < ver {
                            return Err(Error::VerificationFailed(
                                "prefix tree has unexpectedly low version counter".to_string(),
                            ));
                        }
                        changed = true;
                        entry = x;
                        ver = ctr;
                    }
                }
            }

            match ptrs.get(&entry) {
                Some(other) => {
                    if ver != *other {
                        return Err(Error::VerificationFailed(
                            "inconsistent versions found".to_string(),
                        ));
                    }
                }
                None => {
                    ptrs.insert(entry, ver);
                }
            };
        }

        if changed {
            data.ptrs = ptrs;
            self.changed = true;
        }

        Ok(())
    }

    fn save(self, storage: &mut dyn LogStore, search_key: &[u8]) -> Result<()> {
        if self.changed {
            if let Some(data) = self.inner {
                storage.set_data(search_key, data)?
            }
        }
        Ok(())
    }
}

/// Returns the TreeHead that would've been issued immediately after the value
/// being searched for in `SearchResponse` was sequenced.
///
/// Most validation is skipped so the SearchResponse MUST already be verified.
pub fn truncate_search_response(
    config: &PublicConfig,
    req: &SearchRequest,
    res: &SearchResponse,
) -> Result<(u64, [u8; 32])> {
    // NOTE: Update this function in tandem with verify_search_internal.

    let index = evaluate_vrf_proof(&res.vrf_proof, &config.vrf_key, &req.search_key)?;

    // Evaluate the SearchProof to find the terminal leaf.
    let full_tree_head = get_proto_field(&res.tree_head)?;
    let tree_size = {
        let tree_head = get_proto_field(&full_tree_head.tree_head)?;
        tree_head.tree_size
    };
    let search_proof = get_proto_field(&res.search)?;

    let guide = ProofGuide::new(req.version, search_proof.pos, tree_size);

    let mut i = 0;
    let mut leaves = HashMap::new();

    let result = guide.consume(|guide, next_id| {
        let step = &search_proof.steps[i];
        let prefix_proof = get_proto_field(&step.prefix)?;
        guide.insert(next_id, prefix_proof.counter);

        // Evaluate the prefix proof and combine it with the commitment to get
        // the value stored in the log.
        let prefix_root = evaluate_prefix(&index, search_proof.pos, prefix_proof)?;
        let commitment = step
            .commitment
            .as_slice()
            .try_into()
            .map_err(|_| MalformedProof)?;
        leaves.insert(next_id, leaf_hash(&prefix_root, commitment));

        i += 1;
        Ok::<(), Error>(())
    })?;

    let (_, result_id) =
        result.expect("truncate_search_response called with search response that is not verified");

    // Evaluate the inclusion proof to get root value.
    let (ids, values) = into_sorted_pairs(leaves);

    let inclusion_proof = get_hash_proof(&search_proof.inclusion)?;

    let early_stop = ids
        .iter()
        .position(|&id| id == result_id)
        .expect("result_id is not an id that was inspected by proof guide");
    let root = truncate_batch_proof(early_stop, &ids, &values, &inclusion_proof)?;

    Ok((result_id + 1, root))
}

fn into_sorted_pairs<K: Ord + Copy, V>(map: HashMap<K, V>) -> (Vec<K>, Vec<V>) {
    let mut pairs = map.into_iter().collect::<Vec<_>>();
    pairs.sort_by_key(|pair| pair.0);
    pairs.into_iter().unzip()
}

#[cfg(test)]
mod test {
    use std::result::Result;

    use assert_matches::assert_matches;
    use hex_literal::hex;
    use prost::Message as _;
    use test_case::test_case;

    use super::*;
    use crate::wire;

    const MAX_AHEAD: Duration = Duration::from_secs(42);
    const MAX_BEHIND: Duration = Duration::from_secs(42);
    const TIMESTAMP_RANGE: &TimestampRange = &TimestampRange {
        max_behind: MAX_BEHIND,
        max_ahead: MAX_AHEAD,
    };

    const ONE_SECOND: Duration = Duration::from_secs(1);

    fn make_timestamp(time: SystemTime) -> i64 {
        let duration = time.duration_since(UNIX_EPOCH).unwrap();
        duration.as_millis().try_into().unwrap()
    }

    #[test_case(SystemTime::now() + MAX_AHEAD + ONE_SECOND; "far ahead")]
    #[test_case(SystemTime::now() - MAX_BEHIND - ONE_SECOND; "far behind")]
    fn verify_timestamps_error(time: SystemTime) {
        let ts = make_timestamp(time);
        assert_matches!(
            verify_timestamp(ts, TIMESTAMP_RANGE, None, SystemTime::now()),
            Err(Error::VerificationFailed(_))
        );
    }

    #[test_case(SystemTime::now(); "now")]
    #[test_case(SystemTime::now() + MAX_AHEAD - ONE_SECOND; "just ahead enough")]
    #[test_case(SystemTime::now() - MAX_BEHIND + ONE_SECOND; "just behind enough")]
    fn verify_timestamps_success(time: SystemTime) {
        let ts = make_timestamp(time);
        assert_matches!(
            verify_timestamp(ts, TIMESTAMP_RANGE, None, SystemTime::now()),
            Ok(())
        );
    }

    struct NullLogStore;

    impl LogStore for NullLogStore {
        fn get_last_tree_head(&self) -> Result<Option<(wire::TreeHead, [u8; 32])>, LogStoreError> {
            Ok(None)
        }

        fn set_last_tree_head(
            &mut self,
            _head: wire::TreeHead,
            _root: [u8; 32],
        ) -> Result<(), LogStoreError> {
            Ok(())
        }

        fn get_data(&self, _key: &[u8]) -> Result<Option<MonitoringData>, LogStoreError> {
            Ok(None)
        }

        fn set_data(&mut self, _key: &[u8], _data: MonitoringData) -> Result<(), LogStoreError> {
            Ok(())
        }
    }

    #[test]
    fn can_verify_search_response() {
        let sig_key = VerifyingKey::from_bytes(&hex!(
            "61eae8fe6373577e6473c5bb65a43b4d86190d78b2e5dc48fa6f253253438fb9"
        ))
        .unwrap();
        let vrf_key = vrf::PublicKey::try_from(hex!(
            "ee964d1552c57c4b8dd9b3f409e6cfd7fb3691966014dbe89f652de7d0a67ca2"
        ))
        .unwrap();
        let request = wire::SearchRequest::decode(
            hex!("0a10b81b5b821e8d4eec8ec5e6513834a9f31a020804").as_slice(),
        )
        .unwrap();
        let response = {
            let bytes = include_bytes!("../res/kt-search-response.dat");
            wire::SearchResponse::decode(bytes.as_slice()).unwrap()
        };
        let valid_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1724796478);
        let config = PublicConfig {
            mode: DeploymentMode::ContactMonitoring,
            signature_key: sig_key,
            vrf_key,
        };
        let mut store = NullLogStore;
        assert_matches!(
            verify_search_internal(&config, &mut store, &request, &response, false, valid_at),
            Ok(())
        )
    }
}
