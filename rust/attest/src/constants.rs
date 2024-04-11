//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hex_literal::hex;

use crate::svr2::RaftConfig;
use crate::util::SmallMap;
use crate::{nitro, tpm2snp};

pub const ENCLAVE_ID_CDSI_STAGING: &[u8] =
    &hex!("0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57");
pub const ENCLAVE_ID_SVR2_STAGING: &[u8] =
    &hex!("acb1973aa0bbbd14b3b4e06f145497d948fd4a98efc500fcce363b3b743ec482");
pub const ENCLAVE_ID_SVR3_SGX_STAGING: &[u8] =
    &hex!("6ac35d9eef8d11f4e6276656f4081925770922e01b7c4d80a51de87d001ac259");
pub const ENCLAVE_ID_SVR3_NITRO_STAGING: &[u8] = b"24e56baa.52b91975.ec540f3f";
pub const ENCLAVE_ID_SVR3_TPM2SNP_STAGING: &[u8] = b"0.20240411.210730";

pub const ENCLAVE_ID_SVR3_SGX_PROD: &[u8] =
    &hex!("0000000000000000000000000000000000000000000000000000000000000000");
pub const ENCLAVE_ID_SVR3_NITRO_PROD: &[u8] = b"00000000.00000000.00000000";
pub const ENCLAVE_ID_SVR3_TPM2SNP_PROD: &[u8] = b"0.00000000.000000";

pub const ENCLAVE_ID_CDSI_PROD: &[u8] = ENCLAVE_ID_CDSI_STAGING;
pub const ENCLAVE_ID_SVR2_PROD: &[u8] =
    &hex!("a6622ad4656e1abcd0bc0ff17c229477747d2ded0495c4ebee7ed35c1789fa97");

pub(crate) const NITRO_EXPECTED_PCRS: SmallMap<&'static [u8], nitro::PcrMap, 1> = SmallMap::new([
    (
        ENCLAVE_ID_SVR3_NITRO_STAGING,
        SmallMap::new([
             (0, hex!("24e56baabe26dcedc58f5753ee979e2f74750df31f43a18f0cf4e08f8ad8c0cd304142cf3441945c3568f4096cb69c66")),
             (1, hex!("52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546")),
             (2, hex!("ec540f3f7f673ab65582d96cf26a747beffcc9392e82f48cfa4ceec47a6ad69a63f9102fc7e1fae37a83a9741814210f")),
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
            (5,  hex!("4e871c2923a78a62db4afde169145ad46c633f871f7a5d14b68153d81d1de4d3")),
            (7,  hex!("590471a4fbd0c881c4fdc6349bc697e4df18c660c3ae3de9cb29028f8ef77280")),
            (8,  hex!("497c436dde91431c96e19e14036cce3a0a70e0dd007b6dcc01f07fbab228c56c")),
            (9,  hex!("9afeee52dee64ac16107982f37f70ffde99126b56e6c1de17c3cb105e4ea6d97")),
            (11, hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            (12, hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            (13, hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            (14, hex!("b9c97933fe323334271a718fdf2966e0609afcb793f3b68aaf18fc31ea39dc0a")),
        ],
    )]);

/// Map from MREnclave to intel SW advisories that are known to be mitigated in the
/// build with that MREnclave value
pub(crate) const ACCEPTABLE_SW_ADVISORIES: &SmallMap<&'static [u8], &'static [&'static str], 3> =
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
    ]);

/// SW advisories known to be mitigated by default. If an MREnclave is provided that
/// is not contained in `ACCEPTABLE_SW_ADVISORIES`, this will be used
pub(crate) const DEFAULT_SW_ADVISORIES: &[&str] = &[];

/// Expected raft configuration for a given enclave.
pub(crate) static EXPECTED_RAFT_CONFIG: SmallMap<&'static [u8], &'static RaftConfig, 5> =
    SmallMap::new([
        (
            ENCLAVE_ID_SVR2_STAGING,
            &RaftConfig {
                min_voting_replicas: 3,
                max_voting_replicas: 5,
                super_majority: 0,
                group_id: 16934825672495360159,
            },
        ),
        (
            ENCLAVE_ID_SVR2_PROD,
            &RaftConfig {
                min_voting_replicas: 4,
                max_voting_replicas: 7,
                super_majority: 2,
                group_id: 1230918306983775578,
            },
        ),
        (
            ENCLAVE_ID_SVR3_SGX_STAGING,
            &RaftConfig {
                min_voting_replicas: 3,
                max_voting_replicas: 9,
                super_majority: 0,
                group_id: 7392562970588785022,
            },
        ),
        (
            ENCLAVE_ID_SVR3_NITRO_STAGING,
            &RaftConfig {
                group_id: 15634566125189380832,
                min_voting_replicas: 3,
                max_voting_replicas: 9,
                super_majority: 0,
            },
        ),
        (
            ENCLAVE_ID_SVR3_TPM2SNP_STAGING,
            &RaftConfig {
                group_id: 8812204445911365918,
                min_voting_replicas: 3,
                max_voting_replicas: 9,
                super_majority: 0,
            },
        ),
    ]);
