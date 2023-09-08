//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;

use hex_literal::hex;
use lazy_static::lazy_static;
use prost::Message;

use crate::dcap::MREnclave;
use crate::proto::svr2;
use crate::sgx_session;
use crate::sgx_session::{Error, Result};

lazy_static! {
    /// Map from MREnclave to intel SW advisories that are known to be mitigated in the
    /// build with that MREnclave value
    static ref ACCEPTABLE_SW_ADVISORIES: HashMap<MREnclave, &'static [&'static str]> = HashMap::from([
        (hex!("a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95"), &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str]),
        (hex!("6ee1042f9e20f880326686dd4ba50c25359f01e9f733eeba4382bca001d45094"), &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str]),
    ]);
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
    static ref EXPECTED_RAFT_CONFIG: HashMap<MREnclave, &'static RaftConfig> = HashMap::from([
        (hex!("a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95"), &RaftConfig {
            min_voting_replicas: 3,
            max_voting_replicas: 5,
            super_majority: 0,
            group_id: 15525669046665930652
        }),
        (hex!("6ee1042f9e20f880326686dd4ba50c25359f01e9f733eeba4382bca001d45094"), &RaftConfig {
            min_voting_replicas: 4,
            max_voting_replicas: 7,
            super_majority: 2,
            group_id: 3950115602363750357
        }),
    ]);
}

pub struct Svr2Handshake {
    /// The attested handshake that can be used to establish a noise connection
    pub handshake: sgx_session::Handshake,

    /// The group_id of the SVR2 raft group we are handshaking with
    pub group_id: u64,
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
) -> Result<sgx_session::Handshake> {
    new_handshake_with_constants(
        mrenclave,
        attestation_msg,
        current_time,
        ACCEPTABLE_SW_ADVISORIES
            .get(mrenclave)
            .unwrap_or(&DEFAULT_SW_ADVISORIES),
        *EXPECTED_RAFT_CONFIG
            .get(mrenclave)
            .ok_or(Error::AttestationDataError {
                reason: format!("unknown mrenclave {:?}", mrenclave),
            })?,
    )
}

fn new_handshake_with_constants(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
    acceptable_sw_advisories: &[&str],
    expected_raft_config: &RaftConfig,
) -> Result<sgx_session::Handshake> {
    // Deserialize attestation handshake start.
    let handshake_start = svr2::ClientHandshakeStart::decode(attestation_msg)?;
    let handshake = sgx_session::Handshake::new(
        mrenclave,
        &handshake_start.evidence,
        &handshake_start.endorsement,
        acceptable_sw_advisories,
        current_time,
    )?;

    let config = handshake
        .custom_claims()
        .get("config")
        .ok_or(Error::AttestationDataError {
            reason: "Claims must contain a raft group config".to_string(),
        })?;

    let actual_config = svr2::RaftGroupConfig::decode(&**config)?;
    if expected_raft_config != &actual_config {
        return Err(Error::AttestationDataError {
            reason: format!("Unexpected raft config {:?}", expected_raft_config),
        });
    }

    Ok(handshake)
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
        let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1683836600);
        let mrenclave_bytes =
            hex!("a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95");
        new_handshake(&mrenclave_bytes, &handshake_bytes, current_time).unwrap();
    }

    #[test]
    fn attest_svr2_bad_config() {
        let handshake_bytes = read_test_file("tests/data/svr2handshakestart.data");
        let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1683836600);
        let mrenclave_bytes =
            hex!("a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95");

        assert!(new_handshake_with_constants(
            &mrenclave_bytes,
            &handshake_bytes,
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
