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
    &hex!("1818c1244de87278c56ca750f333196d8a3e17c1d2078d333b16355807895a9f");
pub const ENCLAVE_ID_SVR3_NITRO_STAGING: &[u8] = b"00902f7b.52b91975.acadd25a";
pub const ENCLAVE_ID_SVR3_TPM2SNP_STAGING: &[u8] = b"0.20240830.211217";

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
             (0, hex!("00902f7bff0858ef8b53b676d4f5581767374d0661e1dfbbd7535c9209276427df4d94c13271032ae1a67366a25fcc42")),
             (1, hex!("52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546")),
             (2, hex!("acadd25abe928f924dbcfd4f62b5f205bb5eea22a563743bc1d2811c6207bcdf6261f4d0b3ef0842252184e371505453")),
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
            (8,  hex!("c187e69bbd55e908629e97add8bf9bee60b17a3b5f41c49799b357addf82a1d4")),
            (9,  hex!("9f339dba0ce95aca07b15926aa09931e07f4f326c4cfd15df390abc45d0a2a83")),
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
    group_id: 4880000078294025403,
};
pub const RAFT_CONFIG_SVR3_NITRO_STAGING: &RaftConfig = &RaftConfig {
    group_id: 18041316560557927763,
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
};
pub const RAFT_CONFIG_SVR3_TPM2SNP_STAGING: &RaftConfig = &RaftConfig {
    group_id: 8573753670372135663,
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
