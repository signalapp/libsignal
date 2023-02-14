//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;

use lazy_static::lazy_static;
use prost::Message;

use crate::dcap::MREnclave;
use crate::proto::svr2;
use crate::sgx_session;
use crate::sgx_session::{Error, Result};

lazy_static! {
    /// Map from MREnclave to intel SW advisories that are known to be mitigated in the
    /// build with that MREnclave value
    static ref ACCEPTABLE_SW_ADVISORIES: HashMap<MREnclave, &'static [&'static str]> = HashMap::new();
}

/// SW advisories known to be mitigated by default. If an MREnclave is provided that
/// is not contained in `ACCEPTABLE_SW_ADVISORIES`, this will be used
const DEFAULT_SW_ADVISORIES: &[&str] = &[];

/// A RaftConfig that can be checked against the attested remote config
#[derive(Debug)]
struct RaftConfig {
    min_voting_replicas: u32,
    max_voting_replicas: u32,
    super_majority: u32,
    group_id: u64,
}

impl PartialEq<svr2::RaftGroupConfig> for RaftConfig {
    fn eq(&self, pb: &svr2::RaftGroupConfig) -> bool {
        pb.min_voting_replicas == self.min_voting_replicas
            && pb.max_voting_replicas == self.max_voting_replicas
            && pb.super_majority == self.super_majority
            && pb.group_id == self.group_id
    }
}

lazy_static! {
    /// Expected raft configuration for a given enclave.
    static ref EXPECTED_RAFT_CONFIG: HashMap<MREnclave, &'static RaftConfig> = HashMap::new();
}

pub struct Svr2Handshake {
    /// The attested handshake that can be used to establish a noise connection
    pub handshake: sgx_session::Handshake,

    /// The group_id of the SVR2 raft group we are handshaking with
    pub group_id: u64,
}

#[allow(dead_code)]
fn validate_raft_config(mrenclave: &[u8], raft_config: &svr2::RaftGroupConfig) -> Result<()> {
    let expected_config =
        *EXPECTED_RAFT_CONFIG
            .get(mrenclave)
            .ok_or(Error::AttestationDataError {
                reason: format!("unknown mrenclave {:?}", mrenclave),
            })?;
    if expected_config != raft_config {
        return Err(Error::AttestationDataError {
            reason: format!("Unexpected raft config {:?}", raft_config),
        });
    }
    Ok(())
}

pub fn new_handshake(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
) -> Result<Svr2Handshake> {
    // Deserialize attestation handshake start.
    let handshake_start = svr2::ClientHandshakeStart::decode(attestation_msg)?;
    let handshake = sgx_session::Handshake::new(
        mrenclave,
        &handshake_start.evidence,
        &handshake_start.endorsement,
        ACCEPTABLE_SW_ADVISORIES
            .get(mrenclave)
            .unwrap_or(&DEFAULT_SW_ADVISORIES),
        current_time,
    )?;

    let config = handshake
        .custom_claims()
        .get("config")
        .ok_or(Error::AttestationDataError {
            reason: "Claims must contain a raft group config".to_string(),
        })?;
    let actual_config = svr2::RaftGroupConfig::decode(&**config)?;

    // Once we have expected server raft configurations, we can validate the raft config too
    // validate_raft_config(mrenclave, &actual_config)?;

    Ok(Svr2Handshake {
        handshake,
        group_id: actual_config.group_id,
    })
}

#[cfg(test)]
mod tests {
    use crate::util::testio::read_test_file;
    use std::time::{Duration, SystemTime};

    use hex_literal::hex;

    use super::*;

    #[test]
    fn attest_svr2() {
        let handshake_bytes = read_test_file("tests/data/svr2handshakestart.data");
        let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1676529724);
        let mrenclave_bytes =
            hex!("f25dfd3b18adc4c0dc190bae1edd603ceca81b42a10b1de52f74db99b338619e");
        new_handshake(&mrenclave_bytes, &handshake_bytes, current_time).unwrap();
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
