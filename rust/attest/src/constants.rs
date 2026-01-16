//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use const_str::hex;

use crate::svr2::RaftConfig;
use crate::util::SmallMap;

/// A helper macro to allow specifying advisories lists conveniently.
macro_rules! advisories {
    (common) => {
        &["INTEL-SA-00615", "INTEL-SA-00657"]
    };
    ($custom:expr) => {
        &$custom
    };
}

/// Defines the list of supported enclaves.
///
/// Does it in a way that is convenient and correct.
///
/// The acceptable SW advisories can be either specified as `common` or as an array of string literals.
///
/// ```text
/// def_enclaves! {
///     MY_ENCLAVE_NAME => ("hex_of_enclave_id", common),
///     MY_OTHER_ENCLAVE_NAME => ("hex_of_enclave_id", ["INTEL-SA-00615"]),
/// }
/// ```
macro_rules! def_enclaves {
    ( $( $name:ident => ( $id_hex:expr , $advisories:tt ) ),* $(,)? ) => {
        $(
            pub const $name: &[u8] = &hex!($id_hex);
        )*

        const ALL_ENCLAVE_IDS: &[&[u8]] = &[
            $( $name, )*
        ];

        const ENCLAVE_COUNT: usize = ALL_ENCLAVE_IDS.len();

        /// Map from MREnclave to intel SW advisories that are known to be mitigated in the
        /// build with that MREnclave value
        pub(crate) const ACCEPTABLE_SW_ADVISORIES: &SmallMap<&'static [u8], &'static [&'static str], ENCLAVE_COUNT> =
            &SmallMap::new([
                $(
                    ($name, advisories!($advisories)),
                )*
            ]);
    };
}

def_enclaves! {
    ENCLAVE_ID_SVR2_2025Q3_STAGING => ("a75542d82da9f6914a1e31f8a7407053b99cc99a0e7291d8fbd394253e19b036", common),
    ENCLAVE_ID_SVR2_2025Q3_PROD => ("29cd63c87bea751e3bfd0fbd401279192e2e5c99948b4ee9437eafc4968355fb", common),
    ENCLAVE_ID_SVRB_2025Q3_STAGING => ("a75542d82da9f6914a1e31f8a7407053b99cc99a0e7291d8fbd394253e19b036", common),
    ENCLAVE_ID_SVRB_2025Q3_PROD => ("aa906dbc85965d37accb660b65a8c224f037b0e7cfd034532acada3592e5b446", common),
    ENCLAVE_ID_SVR2_2026Q1_STAGING => ("97f151f6ed078edbbfd72fa9cae694dcc08353f1f5e8d9ccd79a971b10ffc535", common),
    ENCLAVE_ID_SVR2_2026Q1_PROD => ("1240acbd4aa26974184844c8a46b1022d3957ac8a76c1fd8f5b1a15141ee0708", common),
    ENCLAVE_ID_SVRB_2026Q1_STAGING => ("97f151f6ed078edbbfd72fa9cae694dcc08353f1f5e8d9ccd79a971b10ffc535", common),
    ENCLAVE_ID_SVRB_2026Q1_PROD => ("bee62050df1072e3d9fdf7660bfaf4e4b71f5622db9de8b30fc5f4b9852d8359", common),
    ENCLAVE_ID_CDSI_STAGING => ("3ded708ca5a42fd84b4639dc661a7ec4b9c9f1b92809c0fc91da2349a5a89d05", common),
    ENCLAVE_ID_CDSI_PROD => ("ee9503070127120074612b6688e593b67e486b1541449f54d71e387484eb40a3", common),
}

/// SW advisories known to be mitigated by default. If an MREnclave is provided that
/// is not contained in `ACCEPTABLE_SW_ADVISORIES`, this will be used
pub(crate) const DEFAULT_SW_ADVISORIES: &[&str] = &[];

/// Expected raft configuration for a given enclave.
pub const RAFT_CONFIG_SVR2_2025Q3_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 14164309227572919775,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVR2_2025Q3_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
    group_id: 10263621230883829694,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVRB_2025Q3_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 5762521016145161874,
    db_version: 4,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVRB_2025Q3_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
    group_id: 17845984565043772621,
    db_version: 4,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVR2_2026Q1_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 2330628069874851020,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVR2_2026Q1_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
    group_id: 2076725645304009823,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVRB_2026Q1_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 1416305463306398324,
    db_version: 4,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVRB_2026Q1_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
    group_id: 16652830871035963553,
    db_version: 4,
    attestation_timeout: 604800,
    simulated: false,
};

// This is left here primarily to support SVR2 bridging code that does
// not expose the notion of environment to the clients.
pub(crate) static EXPECTED_RAFT_CONFIG_SVR2: SmallMap<&'static [u8], &'static RaftConfig, 4> =
    SmallMap::new([
        (
            ENCLAVE_ID_SVR2_2025Q3_STAGING,
            RAFT_CONFIG_SVR2_2025Q3_STAGING,
        ),
        (ENCLAVE_ID_SVR2_2025Q3_PROD, RAFT_CONFIG_SVR2_2025Q3_PROD),
        (
            ENCLAVE_ID_SVR2_2026Q1_STAGING,
            RAFT_CONFIG_SVR2_2026Q1_STAGING,
        ),
        (ENCLAVE_ID_SVR2_2026Q1_PROD, RAFT_CONFIG_SVR2_2026Q1_PROD),
    ]);
