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
    &hex!("b7811fb574a4d7e59408e30a2e0ddd9ae3f241594156e7ad647785c1c52e4f3c");
pub const ENCLAVE_ID_SVR3_NITRO_STAGING: &[u8] = b"3b3dda58.52b91975.02dfde15";
pub const ENCLAVE_ID_SVR3_TPM2SNP_STAGING: &[u8] = b"0.20240319.160523";

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
             (0, hex!("3b3dda58fb82066920ecb191a41a21680651cb94c7b25e806f0999c6c30c53797779df4677fcd19bdb726c0ba1a77bca")),
             (1, hex!("52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546")),
             (2, hex!("02dfde151591cc1fcc08f9c9e29c588562c98436743b7f7cd895ad594391b42c405c52e6265ea03b28bf88ef7bf28661")),
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
            (5,  hex!("076726dc15276afd9cc9d7574340e1de96934782939e5a8cbac1ca5158061404")),
            (7,  hex!("ba313dc4774eb6ddcc01945c2b57dbfb1afc296de9ff8105f916b4f55afa848a")),
            (8,  hex!("5315286db60934c840f5a894dd79e36a12b6cfa4ffe199f929d0b8f4be9e5aa9")),
            (9,  hex!("0fde941f5c73bfc4b19d53a5db1abc886c4c1308d665194d373677a55f683c2e")),
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
                max_voting_replicas: 5,
                super_majority: 0,
                group_id: 1292240360480775808,
            },
        ),
        (
            ENCLAVE_ID_SVR3_NITRO_STAGING,
            &RaftConfig {
                group_id: 12002677302519264339,
                min_voting_replicas: 3,
                max_voting_replicas: 5,
                super_majority: 0,
            },
        ),
        (
            ENCLAVE_ID_SVR3_TPM2SNP_STAGING,
            &RaftConfig {
                group_id: 2616274069462536786,
                min_voting_replicas: 3,
                max_voting_replicas: 5,
                super_majority: 0,
            },
        ),
    ]);
