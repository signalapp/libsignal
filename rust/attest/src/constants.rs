//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use const_str::hex;

use crate::svr2::RaftConfig;
use crate::util::SmallMap;

pub(crate) const SGX_TCB_EVALUATION_DATA_NUMBER_MIN: u16 = 21;

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
    ENCLAVE_ID_SVR2_2026Q1_STAGING => ("97f151f6ed078edbbfd72fa9cae694dcc08353f1f5e8d9ccd79a971b10ffc535", common),
    ENCLAVE_ID_SVR2_2026Q1_PROD => ("1240acbd4aa26974184844c8a46b1022d3957ac8a76c1fd8f5b1a15141ee0708", common),
    ENCLAVE_ID_SVRB_2026Q1_STAGING => ("97f151f6ed078edbbfd72fa9cae694dcc08353f1f5e8d9ccd79a971b10ffc535", common),
    ENCLAVE_ID_SVRB_2026Q1_PROD => ("bee62050df1072e3d9fdf7660bfaf4e4b71f5622db9de8b30fc5f4b9852d8359", common),
    ENCLAVE_ID_SVR2_2026Q2_STAGING => ("3c699f4975aaa3d172c0aad042f94f031b2b03e10b9c19a45116a01693d83302", common),
    ENCLAVE_ID_SVR2_2026Q2_PROD => ("ced8217b26228e4b210c985786999d095c4958a94faf37b14acaf25c4cbb02a4", common),
    ENCLAVE_ID_SVRB_2026Q2_STAGING => ("3c699f4975aaa3d172c0aad042f94f031b2b03e10b9c19a45116a01693d83302", common),
    ENCLAVE_ID_SVRB_2026Q2_PROD => ("2048e20fcd07d0992c4907e8e04c5a85f1f993d195004c7342675343ca2e524b", common),
    ENCLAVE_ID_SVR2_2026Q3_STAGING_V1 => ("c9e8a0c4ead9434c1c66004fed3e186dd184299c216bc33359e46745c0fc7e16", common),
    ENCLAVE_ID_SVR2_2026Q3_STAGING => ("0ff2d7d4efbe7cfc24ac069a16fba898928dbe6c40d500c8b6da55733c727d6e", common),
    ENCLAVE_ID_SVR2_2026Q3_PROD => ("fdbbacdc0c043d0d53fe1440f62728de0386f45ab0a275bd8f99e03a02af355e", common),
    ENCLAVE_ID_SVRB_2026Q3_STAGING => ("0ff2d7d4efbe7cfc24ac069a16fba898928dbe6c40d500c8b6da55733c727d6e", common),
    ENCLAVE_ID_SVRB_2026Q3_PROD => ("fdbbacdc0c043d0d53fe1440f62728de0386f45ab0a275bd8f99e03a02af355e", common),

    ENCLAVE_ID_CDSI_STAGING => ("6d9b9649fa3a337754a98059c66d48ac77aaca5299d3b27d6ed1e646c7c81c0a", common),
    ENCLAVE_ID_CDSI_PROD => ("15637fa1e54fe655176d3df1a9f94b87c01ed377acaa570682dc5d72c95ef07b", common),
}

/// SW advisories known to be mitigated by default. If an MREnclave is provided that
/// is not contained in `ACCEPTABLE_SW_ADVISORIES`, this will be used
pub(crate) const DEFAULT_SW_ADVISORIES: &[&str] = &[];

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

pub const RAFT_CONFIG_SVR2_2026Q2_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 5138641357881452604,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVR2_2026Q2_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
    group_id: 11311619198250676136,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVRB_2026Q2_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 11614651745041226414,
    db_version: 4,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVRB_2026Q2_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
    group_id: 15457520608692442134,
    db_version: 4,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVR2_2026Q3_STAGING_V1: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 10062002712960068502,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVR2_2026Q3_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 12510703925871071514,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVRB_2026Q3_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 13648120821105181316,
    db_version: 4,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVR2_2026Q3_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
    group_id: 9849236121871729655,
    db_version: 2,
    attestation_timeout: 604800,
    simulated: false,
};

pub const RAFT_CONFIG_SVRB_2026Q3_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 13,
    super_majority: 2,
    group_id: 14899358270260239030,
    db_version: 4,
    attestation_timeout: 604800,
    simulated: false,
};

// This is left here primarily to support SVR2 bridging code that does
// not expose the notion of environment to the clients.
pub(crate) static EXPECTED_RAFT_CONFIG_SVR2: SmallMap<&'static [u8], &'static RaftConfig, 7> =
    SmallMap::new([
        (
            ENCLAVE_ID_SVR2_2026Q1_STAGING,
            RAFT_CONFIG_SVR2_2026Q1_STAGING,
        ),
        (ENCLAVE_ID_SVR2_2026Q1_PROD, RAFT_CONFIG_SVR2_2026Q1_PROD),
        (
            ENCLAVE_ID_SVR2_2026Q2_STAGING,
            RAFT_CONFIG_SVR2_2026Q2_STAGING,
        ),
        (ENCLAVE_ID_SVR2_2026Q2_PROD, RAFT_CONFIG_SVR2_2026Q2_PROD),
        (
            ENCLAVE_ID_SVR2_2026Q3_STAGING_V1,
            RAFT_CONFIG_SVR2_2026Q3_STAGING_V1,
        ),
        (
            ENCLAVE_ID_SVR2_2026Q3_STAGING,
            RAFT_CONFIG_SVR2_2026Q3_STAGING,
        ),
        (ENCLAVE_ID_SVR2_2026Q3_PROD, RAFT_CONFIG_SVR2_2026Q3_PROD),
    ]);

/// If true, we will skip enforcement of TCB minimums reported
/// by SVR.  If false, enforcement will be applied.
pub(crate) fn skip_tcb_minimums_enforcement_svr(mrenclave: &[u8]) -> bool {
    const TO_SKIP: &[&[u8]] = &[
        ENCLAVE_ID_SVR2_2026Q1_STAGING,
        ENCLAVE_ID_SVR2_2026Q1_PROD,
        ENCLAVE_ID_SVR2_2026Q2_STAGING,
        ENCLAVE_ID_SVR2_2026Q2_PROD,
        ENCLAVE_ID_SVRB_2026Q1_STAGING,
        ENCLAVE_ID_SVRB_2026Q1_PROD,
        ENCLAVE_ID_SVRB_2026Q2_STAGING,
        ENCLAVE_ID_SVRB_2026Q2_PROD,
    ];
    // We should never add any new SVR enclaves to this map.
    const _SKIP_TCB_MINIMUMS_ENFORCEMENT_SVR_DOES_NOT_GROW: () = assert!(TO_SKIP.len() <= 8);
    TO_SKIP.contains(&mrenclave)
}
