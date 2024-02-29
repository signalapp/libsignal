//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hex_literal::hex;

use crate::nitro::PcrMap;
use crate::svr2::RaftConfig;
use crate::util::SmallMap;

pub const ENCLAVE_ID_CDSI_STAGING: &[u8] =
    &hex!("0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57");
pub const ENCLAVE_ID_SVR2_STAGING: &[u8] =
    &hex!("acb1973aa0bbbd14b3b4e06f145497d948fd4a98efc500fcce363b3b743ec482");
pub const ENCLAVE_ID_SVR3_SGX_STAGING: &[u8] =
    &hex!("b7811fb574a4d7e59408e30a2e0ddd9ae3f241594156e7ad647785c1c52e4f3c");
pub const ENCLAVE_ID_SVR3_NITRO_STAGING: &[u8] = b"3b3dda58.52b91975.02dfde15";

pub const ENCLAVE_ID_CDSI_PROD: &[u8] = ENCLAVE_ID_CDSI_STAGING;
pub const ENCLAVE_ID_SVR2_PROD: &[u8] =
    &hex!("a6622ad4656e1abcd0bc0ff17c229477747d2ded0495c4ebee7ed35c1789fa97");

pub(crate) const NITRO_EXPECTED_PCRS: SmallMap<&'static [u8], PcrMap, 1>  = SmallMap::new([
    (
        ENCLAVE_ID_SVR3_NITRO_STAGING,
        SmallMap::new([
             (0, hex!("3b3dda58fb82066920ecb191a41a21680651cb94c7b25e806f0999c6c30c53797779df4677fcd19bdb726c0ba1a77bca")),
             (1, hex!("52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546")),
             (2, hex!("02dfde151591cc1fcc08f9c9e29c588562c98436743b7f7cd895ad594391b42c405c52e6265ea03b28bf88ef7bf28661")),
        ]),
    ),
]);

/// Map from MREnclave to intel SW advisories that are known to be mitigated in the
/// build with that MREnclave value
pub(crate) const ACCEPTABLE_SW_ADVISORIES: &SmallMap<&'static [u8], &'static [&'static str], 5> =
    &SmallMap::new([
        (
            // Previous SVR2 staging
            &hex!("a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95"),
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            // Previous SVR2 prod
            &hex!("6ee1042f9e20f880326686dd4ba50c25359f01e9f733eeba4382bca001d45094"),
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
            ENCLAVE_ID_SVR3_SGX_STAGING,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
    ]);

/// SW advisories known to be mitigated by default. If an MREnclave is provided that
/// is not contained in `ACCEPTABLE_SW_ADVISORIES`, this will be used
pub(crate) const DEFAULT_SW_ADVISORIES: &[&str] = &[];

/// Expected raft configuration for a given enclave.
pub(crate) static EXPECTED_RAFT_CONFIG: SmallMap<&'static [u8], &'static RaftConfig, 6> =
    SmallMap::new([
        (
            // Previous SVR2 staging
            &hex!("a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95"),
            &RaftConfig {
                min_voting_replicas: 3,
                max_voting_replicas: 5,
                super_majority: 0,
                group_id: 15525669046665930652,
            },
        ),
        (
            // Previous SVR2 prod
            &hex!("6ee1042f9e20f880326686dd4ba50c25359f01e9f733eeba4382bca001d45094"),
            &RaftConfig {
                min_voting_replicas: 4,
                max_voting_replicas: 7,
                super_majority: 2,
                group_id: 3950115602363750357,
            },
        ),
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
    ]);
