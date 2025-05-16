//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use const_str::hex;

use crate::svr2::RaftConfig;
use crate::util::SmallMap;

pub const ENCLAVE_ID_CDSI: &[u8] =
    &hex!("c00d6f734e922f4b312ee3517680838e1dd951878b721cd0d09edb817da47389");
pub const ENCLAVE_ID_CDSI_PREQUANTUM: &[u8] =
    &hex!("c00d6f734e922f4b312ee3517680838e1dd951878b721cd0d09edb817da47389");

pub const ENCLAVE_ID_SVR2_STAGING: &[u8] =
    &hex!("38e01eff4fe357dc0b0e8ef7a44b4abc5489fbccba3a78780f3872c277f62bf3");
pub const ENCLAVE_ID_SVR2_PROD: &[u8] =
    &hex!("9314436a9a144992bb3680770ea5fd7934a7ffd29257844a33763a238903d570");

/// Map from MREnclave to intel SW advisories that are known to be mitigated in the
/// build with that MREnclave value
pub(crate) const ACCEPTABLE_SW_ADVISORIES: &SmallMap<&'static [u8], &'static [&'static str], 2> =
    &SmallMap::new([
        (
            ENCLAVE_ID_SVR2_STAGING,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            ENCLAVE_ID_SVR2_PROD,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
    ]);

/// SW advisories known to be mitigated by default. If an MREnclave is provided that
/// is not contained in `ACCEPTABLE_SW_ADVISORIES`, this will be used
pub(crate) const DEFAULT_SW_ADVISORIES: &[&str] = &[];

/// Expected raft configuration for a given enclave.
pub const RAFT_CONFIG_SVR2_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 5,
    super_majority: 0,
    group_id: 3565209795906488720,
};

pub const RAFT_CONFIG_SVR2_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 7,
    super_majority: 2,
    group_id: 13627152585634424319,
};

// This is left here primarily to support SVR2 bridging code that does
// not expose the notion of environment to the clients.
pub(crate) static EXPECTED_RAFT_CONFIG_SVR2: SmallMap<&'static [u8], &'static RaftConfig, 2> =
    SmallMap::new([
        (ENCLAVE_ID_SVR2_STAGING, RAFT_CONFIG_SVR2_STAGING),
        (ENCLAVE_ID_SVR2_PROD, RAFT_CONFIG_SVR2_PROD),
    ]);
