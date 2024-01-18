//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hex_literal::hex;

use prost::Message;

use crate::dcap::MREnclave;
use crate::enclave::{Error, Handshake, Result};
use crate::proto::svr2;
use crate::util::SmallMap;

/// Map from MREnclave to intel SW advisories that are known to be mitigated in the
/// build with that MREnclave value
const ACCEPTABLE_SW_ADVISORIES: &SmallMap<MREnclave, &'static [&'static str], 5> =
    &SmallMap::new([
        (
            hex!("a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95"),
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            hex!("6ee1042f9e20f880326686dd4ba50c25359f01e9f733eeba4382bca001d45094"),
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            hex!("acb1973aa0bbbd14b3b4e06f145497d948fd4a98efc500fcce363b3b743ec482"),
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            hex!("a6622ad4656e1abcd0bc0ff17c229477747d2ded0495c4ebee7ed35c1789fa97"),
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
        (
            hex!("5db9423ed5a0b0bef374eac3a8251839e1f63ed40a2537415b63656b26912d92"),
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
        ),
    ]);

/// SW advisories known to be mitigated by default. If an MREnclave is provided that
/// is not contained in `ACCEPTABLE_SW_ADVISORIES`, this will be used
const DEFAULT_SW_ADVISORIES: &[&str] = &[];

/// A RaftConfig that can be checked against the attested remote config
#[derive(Debug)]
pub struct RaftConfig {
    pub min_voting_replicas: u32,
    pub max_voting_replicas: u32,
    pub super_majority: u32,
    pub group_id: u64,
}

impl PartialEq<svr2::RaftGroupConfig> for RaftConfig {
    fn eq(&self, pb: &svr2::RaftGroupConfig) -> bool {
        pb.min_voting_replicas == self.min_voting_replicas
            && pb.max_voting_replicas == self.max_voting_replicas
            && pb.super_majority == self.super_majority
            && pb.group_id == self.group_id
    }
}

/// Expected raft configuration for a given enclave.
static EXPECTED_RAFT_CONFIG: SmallMap<MREnclave, &'static RaftConfig, 5> = SmallMap::new([
    (
        hex!("a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95"),
        &RaftConfig {
            min_voting_replicas: 3,
            max_voting_replicas: 5,
            super_majority: 0,
            group_id: 15525669046665930652,
        },
    ),
    (
        hex!("6ee1042f9e20f880326686dd4ba50c25359f01e9f733eeba4382bca001d45094"),
        &RaftConfig {
            min_voting_replicas: 4,
            max_voting_replicas: 7,
            super_majority: 2,
            group_id: 3950115602363750357,
        },
    ),
    (
        hex!("acb1973aa0bbbd14b3b4e06f145497d948fd4a98efc500fcce363b3b743ec482"),
        &RaftConfig {
            min_voting_replicas: 3,
            max_voting_replicas: 5,
            super_majority: 0,
            group_id: 16934825672495360159,
        },
    ),
    (
        hex!("a6622ad4656e1abcd0bc0ff17c229477747d2ded0495c4ebee7ed35c1789fa97"),
        &RaftConfig {
            min_voting_replicas: 4,
            max_voting_replicas: 7,
            super_majority: 2,
            group_id: 1230918306983775578,
        },
    ),
    (
        // svr3 staging
        hex!("5db9423ed5a0b0bef374eac3a8251839e1f63ed40a2537415b63656b26912d92"),
        &RaftConfig {
            min_voting_replicas: 3,
            max_voting_replicas: 5,
            super_majority: 0,
            group_id: 13862729870901000330,
        },
    ),
]);

pub(crate) fn expected_raft_config(
    mr_enclave: &[u8],
    config_override: Option<&'static RaftConfig>,
) -> Result<&'static RaftConfig> {
    config_override
        .or_else(|| EXPECTED_RAFT_CONFIG.get(mr_enclave).copied())
        .ok_or(Error::AttestationDataError {
            reason: format!("unknown mrenclave {:?}", mr_enclave),
        })
}
/// Lookup the group id constant associated with the `mrenclave`
pub fn lookup_groupid(mrenclave: &[u8]) -> Option<u64> {
    EXPECTED_RAFT_CONFIG
        .get(mrenclave)
        .map(|config| config.group_id)
}

pub fn new_handshake(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
) -> Result<Handshake> {
    new_handshake_with_override(mrenclave, attestation_msg, current_time, None)
}

pub fn new_handshake_with_override(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
    raft_config_override: Option<&'static RaftConfig>,
) -> Result<Handshake> {
    let expected_raft_config = expected_raft_config(mrenclave, raft_config_override)?;
    new_handshake_with_constants(
        mrenclave,
        attestation_msg,
        current_time,
        ACCEPTABLE_SW_ADVISORIES
            .get(mrenclave)
            .unwrap_or(&DEFAULT_SW_ADVISORIES),
        expected_raft_config,
    )
}

fn new_handshake_with_constants(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
    acceptable_sw_advisories: &[&str],
    expected_raft_config: &RaftConfig,
) -> Result<Handshake> {
    // Deserialize attestation handshake start.
    let handshake_start = svr2::ClientHandshakeStart::decode(attestation_msg)?;
    let handshake = Handshake::for_sgx(
        mrenclave,
        &handshake_start.evidence,
        &handshake_start.endorsement,
        acceptable_sw_advisories,
        current_time,
    )?
    .validate(expected_raft_config)?;

    Ok(handshake)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use hex_literal::hex;

    use super::*;

    #[test]
    fn attest_svr2() {
        const HANDSHAKE_BYTES: &[u8] = include_bytes!("../tests/data/svr2handshakestart.data");
        let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1683836600);
        let mrenclave_bytes =
            hex!("a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95");
        new_handshake(&mrenclave_bytes, HANDSHAKE_BYTES, current_time).unwrap();
    }

    #[test]
    fn attest_svr2_bad_config() {
        const HANDSHAKE_BYTES: &[u8] = include_bytes!("../tests/data/svr2handshakestart.data");
        let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1683836600);
        let mrenclave_bytes =
            hex!("a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95");

        assert!(new_handshake_with_constants(
            &mrenclave_bytes,
            HANDSHAKE_BYTES,
            current_time,
            &[],
            &RaftConfig {
                min_voting_replicas: 3,
                max_voting_replicas: 5,
                super_majority: 0,
                group_id: 0, // wrong
            },
        )
        .is_err());
    }

    fn matches(
        min_voting_replicas: u32,
        max_voting_replicas: u32,
        super_majority: u32,
        group_id: u64,
        expected: &RaftConfig,
    ) -> bool {
        expected
            == &svr2::RaftGroupConfig {
                min_voting_replicas,
                max_voting_replicas,
                super_majority,
                group_id,
            }
    }

    #[test]
    fn raft_config_matches() {
        let expected = RaftConfig {
            min_voting_replicas: 3,
            max_voting_replicas: 4,
            super_majority: 1,
            group_id: 12345,
        };
        // valid
        assert!(matches(3, 4, 1, 12345, &expected));

        // invalid
        assert!(!matches(2, 4, 1, 12345, &expected));
        assert!(!matches(3, 3, 1, 12345, &expected));
        assert!(!matches(3, 4, 0, 12345, &expected));
        assert!(!matches(3, 4, 1, 54321, &expected));
    }
}
