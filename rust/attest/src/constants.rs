//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hex_literal::hex;

use crate::svr2::RaftConfig;
use crate::util::SmallMap;
use crate::{nitro, tpm2snp};

pub const ENCLAVE_ID_CDSI_STAGING_AND_PROD: &[u8] =
    &hex!("0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57");
pub const ENCLAVE_ID_SVR2_STAGING: &[u8] =
    &hex!("acb1973aa0bbbd14b3b4e06f145497d948fd4a98efc500fcce363b3b743ec482");
pub const ENCLAVE_ID_SVR3_SGX_STAGING: &[u8] =
    &hex!("29cd5aa268da2412ae14e9de2168608c9b22daadfd7effa2029abac02289e691");
pub const ENCLAVE_ID_SVR3_NITRO_STAGING: &[u8] = b"ffe631d7.52b91975.a4544fb5";
pub const ENCLAVE_ID_SVR3_TPM2SNP_STAGING: &[u8] = b"0.20240510.172959";

pub const ENCLAVE_ID_SVR3_SGX_PROD: &[u8] =
    &hex!("0899bf951b57f27b5cd3d2dd4dbe5a144a4a62154853a4e352ac2c93ecfe6a2c");
pub const ENCLAVE_ID_SVR3_NITRO_PROD: &[u8] = ENCLAVE_ID_SVR3_NITRO_STAGING;
pub const ENCLAVE_ID_SVR3_TPM2SNP_PROD: &[u8] = ENCLAVE_ID_SVR3_TPM2SNP_STAGING;

pub const ENCLAVE_ID_SVR2_PROD: &[u8] =
    &hex!("a6622ad4656e1abcd0bc0ff17c229477747d2ded0495c4ebee7ed35c1789fa97");

pub(crate) const NITRO_EXPECTED_PCRS: SmallMap<&'static [u8], nitro::PcrMap, 1> = SmallMap::new([
    (
        ENCLAVE_ID_SVR3_NITRO_STAGING,
        SmallMap::new([
             (0, hex!("ffe631d7b726c672480ddde425f3ed9cbdaafa354dc6a85277dde6bfca56e93fafd66052f1dd93bf5f240c5a55fb2cb1")),
             (1, hex!("52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546")),
             (2, hex!("a4544fb5e5f416c08c4aca4c3f14efaf8d16d7ddc39d15f17b3b02605ef6e3a834553a0901fbce8716cc0de8caea028d")),
        ]),
    ),
]);

// Manually format the following to keep the indexes and hexstrings on the same line.
#[rustfmt::skip]
pub(crate) const TPM2SNP_EXPECTED_PCRS: SmallMap<&'static [u8], &'static tpm2snp::PcrMap, 1> =
    SmallMap::new([(
        ENCLAVE_ID_SVR3_TPM2SNP_STAGING,
        &[
            (2,  hex!("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969")),
            (3,  hex!("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969")),
            (4,  hex!("6038382cdf539eb64d05c804c510e22b81e2c71fb171c9616ab14504f3654bb1")),
            (7,  hex!("590471a4fbd0c881c4fdc6349bc697e4df18c660c3ae3de9cb29028f8ef77280")),
            (8,  hex!("48f56c81de21292cd225485ec0ba268497662a1bfcdf5ef65d0b03bbc0d0c4d9")),
            (9,  hex!("626d155ba40667ab3cb4385102c89e0b7ffd1a8348da20653e4f651ea0152e32")),
            (11, hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            (12, hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            (13, hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            (14, hex!("b9c97933fe323334271a718fdf2966e0609afcb793f3b68aaf18fc31ea39dc0a")),
        ],
    )]);

/// Map from MREnclave to intel SW advisories that are known to be mitigated in the
/// build with that MREnclave value
pub(crate) const ACCEPTABLE_SW_ADVISORIES: &SmallMap<&'static [u8], &'static [&'static str], 4> =
    &SmallMap::new([
        (
            ENCLAVE_ID_SVR2_STAGING,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            ENCLAVE_ID_SVR2_PROD,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            ENCLAVE_ID_SVR3_SGX_STAGING,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            ENCLAVE_ID_SVR3_SGX_PROD,
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
    group_id: 16934825672495360159,
};

pub const RAFT_CONFIG_SVR2_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 7,
    super_majority: 2,
    group_id: 1230918306983775578,
};

pub const RAFT_CONFIG_SVR3_SGX_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 15742431669367858463,
};
pub const RAFT_CONFIG_SVR3_NITRO_STAGING: &RaftConfig = &RaftConfig {
    group_id: 10298929430185113734,
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
};
pub const RAFT_CONFIG_SVR3_TPM2SNP_STAGING: &RaftConfig = &RaftConfig {
    group_id: 8572438378773168949,
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
};
pub const RAFT_CONFIG_SVR3_SGX_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
    group_id: 9590812984166600424,
};
pub const RAFT_CONFIG_SVR3_NITRO_PROD: &RaftConfig = &RaftConfig {
    group_id: 13958530449904196066,
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
};
pub const RAFT_CONFIG_SVR3_TPM2SNP_PROD: &RaftConfig = &RaftConfig {
    group_id: 6899183880775443455,
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
};

// This is left here primarily to support SVR2 bridging code that does
// not expose the notion of environment to the clients.
pub(crate) static EXPECTED_RAFT_CONFIG_SVR2: SmallMap<&'static [u8], &'static RaftConfig, 2> =
    SmallMap::new([
        (ENCLAVE_ID_SVR2_STAGING, RAFT_CONFIG_SVR2_STAGING),
        (ENCLAVE_ID_SVR2_PROD, RAFT_CONFIG_SVR2_PROD),
    ]);
