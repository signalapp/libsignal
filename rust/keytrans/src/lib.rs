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
use verify::{
    truncate_search_response, verify_distinguished, verify_monitor, verify_search, verify_update,
};
pub use vrf::PublicKey as VrfPublicKey;
pub use wire::{
    Consistency, FullTreeHead, MonitorKey, MonitorRequest, MonitorResponse, SearchRequest,
    SearchResponse, TreeHead, UpdateRequest, UpdateResponse, UpdateValue,
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

#[derive(Default, Debug)]
pub struct SearchContext {
    last_tree_head: Option<LastTreeHead>,
    data: Option<MonitoringData>,
}

#[derive(Default, Debug)]
pub struct MonitorContext {
    last_tree_head: Option<LastTreeHead>,
    data: HashMap<Vec<u8>, MonitoringData>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum DataUpdate<T> {
    Unchanged,
    Changed(T),
}

#[derive(Debug)]
pub struct SearchUpdate {
    pub tree_head: TreeHead,
    pub tree_root: TreeRoot,
    pub data: DataUpdate<MonitoringData>,
}

#[derive(Debug)]
pub struct MonitorUpdate<'a> {
    pub tree_head: TreeHead,
    pub tree_root: TreeRoot,
    pub data: Vec<(&'a [u8], DataUpdate<MonitoringData>)>,
}

/// PublicConfig wraps the cryptographic keys needed to interact with a
/// transparency tree.
#[derive(Clone)]
pub struct PublicConfig {
    pub mode: DeploymentMode,
    pub signature_key: VerifyingKey,
    pub vrf_key: vrf::PublicKey,
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
        &mut self,
        request: SearchRequest,
        response: SearchResponse,
        context: SearchContext,
        force_monitor: bool,
        now: SystemTime,
    ) -> Result<SearchUpdate, verify::Error> {
        verify_search(&self.config, request, response, context, force_monitor, now)
    }

    /// Checks that the provided FullTreeHead has a valid consistency proof relative
    /// to the provided distinguished head.
    pub fn verify_distinguished(
        &mut self,
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
        &mut self,
        request: &SearchRequest,
        response: &SearchResponse,
    ) -> Result<(u64, [u8; 32]), verify::Error> {
        truncate_search_response(&self.config, request, response)
    }

    /// Checks that the output of a Monitor operation is valid and updates the
    /// client's stored data.
    pub fn verify_monitor<'a>(
        &'a mut self,
        request: &'a MonitorRequest,
        response: &'a MonitorResponse,
        context: MonitorContext,
        now: SystemTime,
    ) -> Result<MonitorUpdate<'a>, verify::Error> {
        verify_monitor(&self.config, request, response, context, now)
    }

    /// Checks that the output of an Update operation is valid and updates the
    /// client's stored data.
    pub fn verify_update(
        &mut self,
        request: &UpdateRequest,
        response: &UpdateResponse,
        context: SearchContext,
        now: SystemTime,
    ) -> Result<SearchUpdate, verify::Error> {
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
