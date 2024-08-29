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
    &hex!("64fd0ab571f2de73665befed1f34862e17cdd3d58201e335be2f68b3f985180f");
pub const ENCLAVE_ID_SVR3_NITRO_STAGING: &[u8] = b"e651a442.52b91975.5c89712f";
pub const ENCLAVE_ID_SVR3_TPM2SNP_STAGING: &[u8] = b"0.20240824.003942";

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
             (0, hex!("e651a442efc3be65a893c7ea3211d3a826b5c0b2102a224df9b42b6a7c0306b8e67553beed4069db0192224a644d80bc")),
             (1, hex!("52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546")),
             (2, hex!("5c89712fd49d4cbebfa1c7f7c59e19a2f94203938647348ebd0dfd20ce3e17b9c7447d3e4856348a89d3c96b5a747a35")),
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
            (8,  hex!("de28c40baca9bdb2024cd5e7a0af223396f8459b2bb14b5edce90ff78bc83c93")),
            (9,  hex!("27117054ad1ca7d2daf5f6dbbc5fb7c3268f460afe6a2933d32d34968a13b12a")),
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
    group_id: 2598856512118716214,
};
pub const RAFT_CONFIG_SVR3_NITRO_STAGING: &RaftConfig = &RaftConfig {
    group_id: 12784208226750162631,
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
};
pub const RAFT_CONFIG_SVR3_TPM2SNP_STAGING: &RaftConfig = &RaftConfig {
    group_id: 15331762113118535803,
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
    group_id: 6022122590068091690,
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
