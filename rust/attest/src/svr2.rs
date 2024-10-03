//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use prost::Message;

use crate::constants::{
    ACCEPTABLE_SW_ADVISORIES, DEFAULT_SW_ADVISORIES, EXPECTED_RAFT_CONFIG_SVR2,
};
use crate::enclave::{Error, Handshake, HandshakeType, Result};
use crate::proto::svr;

/// A RaftConfig that can be checked against the attested remote config
#[derive(Debug)]
pub struct RaftConfig {
    pub min_voting_replicas: u32,
    pub max_voting_replicas: u32,
    pub super_majority: u32,
    pub group_id: u64,
}

impl PartialEq<svr::RaftGroupConfig> for RaftConfig {
    fn eq(&self, pb: &svr::RaftGroupConfig) -> bool {
        pb.min_voting_replicas == self.min_voting_replicas
            && pb.max_voting_replicas == self.max_voting_replicas
            && pb.super_majority == self.super_majority
            && pb.group_id == self.group_id
    }
}

/// Lookup the group id constant associated with the `mrenclave`
pub fn lookup_groupid(mrenclave: &[u8]) -> Option<u64> {
    EXPECTED_RAFT_CONFIG_SVR2
        .get(&mrenclave)
        .map(|config| config.group_id)
}

// Must only be used for SVR2 bridging code that does
// not expose the notion of environment to the clients.
pub fn new_handshake_with_raft_config_lookup(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
    handshake_type: HandshakeType,
) -> Result<Handshake> {
    let expected_raft_config =
        EXPECTED_RAFT_CONFIG_SVR2
            .get(&mrenclave)
            .copied()
            .ok_or(Error::AttestationDataError {
                reason: format!("unknown mrenclave {:?}", &mrenclave),
            })?;
    new_handshake(
        mrenclave,
        attestation_msg,
        current_time,
        expected_raft_config,
        handshake_type,
    )
}

pub fn new_handshake(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
    expected_raft_config: &'static RaftConfig,
    handshake_type: HandshakeType,
) -> Result<Handshake> {
    new_handshake_with_constants(
        mrenclave,
        attestation_msg,
        current_time,
        ACCEPTABLE_SW_ADVISORIES
            .get(&mrenclave)
            .unwrap_or(&DEFAULT_SW_ADVISORIES),
        expected_raft_config,
        handshake_type,
    )
}

fn new_handshake_with_constants(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
    acceptable_sw_advisories: &[&str],
    expected_raft_config: &RaftConfig,
    handshake_type: HandshakeType,
) -> Result<Handshake> {
    // Deserialize attestation handshake start.
    let handshake_start = svr::ClientHandshakeStart::decode(attestation_msg)?;
    let handshake = Handshake::for_sgx(
        mrenclave,
        &handshake_start.evidence,
        &handshake_start.endorsement,
        acceptable_sw_advisories,
        current_time,
        handshake_type,
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
        let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1709245753);
        let mrenclave_bytes =
            hex!("acb1973aa0bbbd14b3b4e06f145497d948fd4a98efc500fcce363b3b743ec482");
        new_handshake_with_constants(
            &mrenclave_bytes,
            HANDSHAKE_BYTES,
            current_time,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
            &RaftConfig {
                min_voting_replicas: 3,
                max_voting_replicas: 5,
                super_majority: 0,
                group_id: 16934825672495360159,
            },
            HandshakeType::PreQuantum,
        )
        .unwrap();
    }

    #[test]
    fn attest_svr2_bad_config() {
        const HANDSHAKE_BYTES: &[u8] = include_bytes!("../tests/data/svr2handshakestart.data");
        let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1709245753);
        let mrenclave_bytes =
            hex!("acb1973aa0bbbd14b3b4e06f145497d948fd4a98efc500fcce363b3b743ec482");

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
            HandshakeType::PreQuantum,
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
            == &svr::RaftGroupConfig {
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
