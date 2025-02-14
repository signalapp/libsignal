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
pub const ENCLAVE_ID_SVR2_STAGING_OLD: &[u8] =
    &hex!("acb1973aa0bbbd14b3b4e06f145497d948fd4a98efc500fcce363b3b743ec482");
pub const ENCLAVE_ID_SVR2_STAGING: &[u8] =
    &hex!("38e01eff4fe357dc0b0e8ef7a44b4abc5489fbccba3a78780f3872c277f62bf3");

pub const ENCLAVE_ID_SVR3_SGX_STAGING: &[u8] =
    &hex!("c49739bec442e209506152e38ae498c3688d32d4f575d7b23a31166b5506c610");
pub const ENCLAVE_ID_SVR3_NITRO_STAGING: &[u8] = b"5d16a1fd.52b91975.6c355155";
pub const ENCLAVE_ID_SVR3_TPM2SNP_STAGING: &[u8] = b"0.20240911.184407";

pub const ENCLAVE_ID_SVR3_SGX_PROD: &[u8] =
    &hex!("38e01eff4fe357dc0b0e8ef7a44b4abc5489fbccba3a78780f3872c277f62bf3");
pub const ENCLAVE_ID_SVR3_NITRO_PROD: &[u8] = b"c4f21f2c.52b91975.6b055bb7";
pub const ENCLAVE_ID_SVR3_TPM2SNP_PROD: &[u8] = b"0.20241002.210040";

pub const ENCLAVE_ID_SVR2_PROD: &[u8] =
    &hex!("9314436a9a144992bb3680770ea5fd7934a7ffd29257844a33763a238903d570");

pub(crate) const NITRO_EXPECTED_PCRS: SmallMap<&'static [u8], nitro::PcrMap, 2> = SmallMap::new([
    (
        ENCLAVE_ID_SVR3_NITRO_STAGING,
        SmallMap::new([
             (0, hex!("5d16a1fdbf39bfcd6265b147e985964fcfe31bb1f319a493c7af8f74234752b21161ea0a8b928ab67bd4765657ef68c6")),
             (1, hex!("52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546")),
             (2, hex!("6c35515508b8d289dd0ffae75c0e6ee57662bdd46d316a623573d9913cf76a4c603924d3f3484478f94757628756763e")),
        ]),
    ),
    (
        ENCLAVE_ID_SVR3_NITRO_PROD,
        SmallMap::new([
             (0, hex!("c4f21f2c7a39f6c95fcb7f81bf3ee4cc28bcb0500936e3b94554c4b8859b5c548e3d3c95806360f9f630a225681e4c7b")),
             (1, hex!("52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546")),
             (2, hex!("6b055bb7d25f5145bb97bf026bf5572b638e43f842dafa844260dadfe2872a363c088e63652105cd2d027d919ce4ddb5")),
        ]),
    ),
]);

// Manually format the following to keep the indexes and hexstrings on the same line.
#[rustfmt::skip]
pub(crate) const TPM2SNP_EXPECTED_PCRS: SmallMap<&'static [u8], &'static tpm2snp::PcrMap, 2> =
    SmallMap::new([
    (
        ENCLAVE_ID_SVR3_TPM2SNP_STAGING,
        &[
            (2,  hex!("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969")),
            (3,  hex!("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969")),
            (4,  hex!("aacb8d01b0f00333bb7b98ebdc101b898bd9fa877ab6ec5813729e2d1334560a")),
            (7,  hex!("571a65e29a131cbdb8d5784031ac9f154a248ae52e56578895f717e5334f3561")),
            (8,  hex!("6ee655a7dc22ee233f27efc6e924fd80711ffc59d9737db38239144b812e464f")),
            (9,  hex!("143a17e81c77ccae4267aab067e1f9562872c7a2759414a3ecc813d3e59de6e6")),
            (11, hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            (12, hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            (13, hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            (14, hex!("b9c97933fe323334271a718fdf2966e0609afcb793f3b68aaf18fc31ea39dc0a")),
        ],
    ),
    (
        ENCLAVE_ID_SVR3_TPM2SNP_PROD,
        &[
            (2,  hex!("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969")),
            (3,  hex!("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969")),
            (4,  hex!("aacb8d01b0f00333bb7b98ebdc101b898bd9fa877ab6ec5813729e2d1334560a")),
            (7,  hex!("571a65e29a131cbdb8d5784031ac9f154a248ae52e56578895f717e5334f3561")),
            (8,  hex!("829400ec08ce2f9aec73cb7ab6836ce94b7929d4dbbff4541d18dd4f26534cfc")),
            (9,  hex!("17b4f456f32223b5c8ddb627219089a727e6c18aa72d64f11c87e45909afc00d")),
            (11, hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            (12, hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            (13, hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            (14, hex!("b9c97933fe323334271a718fdf2966e0609afcb793f3b68aaf18fc31ea39dc0a")),
        ],
    ),
    ]);

/// Map from MREnclave to intel SW advisories that are known to be mitigated in the
/// build with that MREnclave value
pub(crate) const ACCEPTABLE_SW_ADVISORIES: &SmallMap<&'static [u8], &'static [&'static str], 5> =
    &SmallMap::new([
        (
            ENCLAVE_ID_SVR2_STAGING_OLD,
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
    group_id: 3565209795906488720,
};
pub const RAFT_CONFIG_SVR2_STAGING_OLD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 5,
    super_majority: 0,
    group_id: 16934825672495360159,
};

pub const RAFT_CONFIG_SVR2_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 4,
    max_voting_replicas: 7,
    super_majority: 2,
    group_id: 13627152585634424319,
};

pub const RAFT_CONFIG_SVR3_SGX_STAGING: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 17325409821474389983,
};
pub const RAFT_CONFIG_SVR3_NITRO_STAGING: &RaftConfig = &RaftConfig {
    group_id: 11362216335221090721,
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
};
pub const RAFT_CONFIG_SVR3_TPM2SNP_STAGING: &RaftConfig = &RaftConfig {
    group_id: 5474905283207641768,
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
};
pub const RAFT_CONFIG_SVR3_SGX_PROD: &RaftConfig = &RaftConfig {
    min_voting_replicas: 1,
    max_voting_replicas: 13,
    super_majority: 0,
    group_id: 17439944065385053815,
};
pub const RAFT_CONFIG_SVR3_NITRO_PROD: &RaftConfig = &RaftConfig {
    group_id: 17667891639367205628,
    min_voting_replicas: 1,
    max_voting_replicas: 13,
    super_majority: 0,
};
pub const RAFT_CONFIG_SVR3_TPM2SNP_PROD: &RaftConfig = &RaftConfig {
    group_id: 14421743284166957665,
    min_voting_replicas: 1,
    max_voting_replicas: 13,
    super_majority: 0,
};

// This is left here primarily to support SVR2 bridging code that does
// not expose the notion of environment to the clients.
pub(crate) static EXPECTED_RAFT_CONFIG_SVR2: SmallMap<&'static [u8], &'static RaftConfig, 3> =
    SmallMap::new([
        (ENCLAVE_ID_SVR2_STAGING_OLD, RAFT_CONFIG_SVR2_STAGING_OLD),
        (ENCLAVE_ID_SVR2_STAGING, RAFT_CONFIG_SVR2_STAGING),
        (ENCLAVE_ID_SVR2_PROD, RAFT_CONFIG_SVR2_PROD),
    ]);
