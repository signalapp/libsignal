//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use const_str::hex;

use crate::enclave::HandshakeType;
use crate::svr2::RaftConfig;
use crate::util::SmallMap;

pub const ENCLAVE_ID_CDSI_STAGING: &[u8] =
    &hex!("3ded708ca5a42fd84b4639dc661a7ec4b9c9f1b92809c0fc91da2349a5a89d05");
pub const ENCLAVE_ID_CDSI_PROD: &[u8] =
    &hex!("ee9503070127120074612b6688e593b67e486b1541449f54d71e387484eb40a3");

pub const ENCLAVE_ID_SVR2_STAGING_PREQUANTUM: &[u8] =
    &hex!("38e01eff4fe357dc0b0e8ef7a44b4abc5489fbccba3a78780f3872c277f62bf3");
pub const ENCLAVE_ID_SVR2_PROD_PREQUANTUM: &[u8] =
    &hex!("9314436a9a144992bb3680770ea5fd7934a7ffd29257844a33763a238903d570");

pub const ENCLAVE_ID_SVR2_STAGING_2025Q2: &[u8] =
    &hex!("2e8cefe6e3f389d8426adb24e9b7fb7adf10902c96f06f7bbcee36277711ed91");
pub const ENCLAVE_ID_SVR2_PROD_2025Q2: &[u8] =
    &hex!("093be9ea32405e85ae28dbb48eb668aebeb7dbe29517b9b86ad4bec4dfe0e6a6");

pub const ENCLAVE_ID_SVR2_STAGING: &[u8] =
    &hex!("a75542d82da9f6914a1e31f8a7407053b99cc99a0e7291d8fbd394253e19b036");
pub const ENCLAVE_ID_SVR2_PROD: &[u8] =
    &hex!("29cd63c87bea751e3bfd0fbd401279192e2e5c99948b4ee9437eafc4968355fb");

pub const ENCLAVE_ID_SVRB_STAGING: &[u8] =
    &hex!("fefd012f3792a5ffd7d385171431adcde938ccb1346d1e1d9d2635da9c44da99");

/// Map from MREnclave to intel SW advisories that are known to be mitigated in the
/// build with that MREnclave value
pub(crate) const ACCEPTABLE_SW_ADVISORIES: &SmallMap<&'static [u8], &'static [&'static str], 7> =
    &SmallMap::new([
        (
            ENCLAVE_ID_SVR2_STAGING_PREQUANTUM,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            ENCLAVE_ID_SVR2_PROD_PREQUANTUM,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            ENCLAVE_ID_SVR2_STAGING_2025Q2,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            ENCLAVE_ID_SVR2_PROD_2025Q2,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            ENCLAVE_ID_SVR2_STAGING,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            ENCLAVE_ID_SVR2_PROD,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            ENCLAVE_ID_SVRB_STAGING,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
    ]);

pub(crate) const SVR2_POSTQUANTUM_OVERRIDE: &SmallMap<&'static [u8], HandshakeType, 2> =
    &SmallMap::new([
        (
            ENCLAVE_ID_SVR2_STAGING_PREQUANTUM,
            HandshakeType::PreQuantum,
        ),
        (ENCLAVE_ID_SVR2_PROD_PREQUANTUM, HandshakeType::PreQuantum),
    ]);

/// SW advisories known to be mitigated by default. If an MREnclave is provided that
/// is not contained in `ACCEPTABLE_SW_ADVISORIES`, this will be used
pub(crate) const DEFAULT_SW_ADVISORIES: &[&str] = &[];

/// Expected raft configuration for a given enclave.
pub const RAFT_CONFIG_SVR2_STAGING_PREQUANTUM: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 5,
    super_majority: 0,
    group_id: 3565209795906488720,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVR2_PROD_PREQUANTUM: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 7,
    super_majority: 2,
    group_id: 13627152585634424319,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};
pub const RAFT_CONFIG_SVR2_STAGING_2025Q2: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 824451999951354968,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVR2_PROD_2025Q2: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
    group_id: 15536668032883538859,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVR2_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 14164309227572919775,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVR2_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
    group_id: 10263621230883829694,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVRB_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 16478507710842799467,
    db_version: 4,
    attestation_timeout: 604800,
    simulated: false,
};

// This is left here primarily to support SVR2 bridging code that does
// not expose the notion of environment to the clients.
pub(crate) static EXPECTED_RAFT_CONFIG_SVR2: SmallMap<&'static [u8], &'static RaftConfig, 6> =
    SmallMap::new([
        (
            ENCLAVE_ID_SVR2_STAGING_PREQUANTUM,
            RAFT_CONFIG_SVR2_STAGING_PREQUANTUM,
        ),
        (
            ENCLAVE_ID_SVR2_PROD_PREQUANTUM,
            RAFT_CONFIG_SVR2_PROD_PREQUANTUM,
        ),
        (
            ENCLAVE_ID_SVR2_STAGING_2025Q2,
            RAFT_CONFIG_SVR2_STAGING_2025Q2,
        ),
        (ENCLAVE_ID_SVR2_PROD_2025Q2, RAFT_CONFIG_SVR2_PROD_2025Q2),
        (ENCLAVE_ID_SVR2_STAGING, RAFT_CONFIG_SVR2_STAGING),
        (ENCLAVE_ID_SVR2_PROD, RAFT_CONFIG_SVR2_PROD),
    ]);
