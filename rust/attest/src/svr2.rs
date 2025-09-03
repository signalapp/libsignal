//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use prost::Message;

use crate::constants::{EXPECTED_RAFT_CONFIG_SVR2, SVR2_POSTQUANTUM_OVERRIDE};
use crate::enclave::{Error, Handshake, HandshakeType, Result};
use crate::proto::svr;
use crate::util::get_sw_advisories;

/// A RaftConfig that can be checked against the attested remote config
#[derive(Debug)]
pub struct RaftConfig {
    pub min_voting_replicas: u32,
    pub max_voting_replicas: u32,
    pub super_majority: u32,
    pub group_id: u64,
    pub db_version: i32,
    pub attestation_timeout: u32,
    pub simulated: bool,
}

impl PartialEq<svr::RaftGroupConfig> for RaftConfig {
    fn eq(&self, pb: &svr::RaftGroupConfig) -> bool {
        pb.min_voting_replicas == self.min_voting_replicas
            && pb.max_voting_replicas == self.max_voting_replicas
            && pb.super_majority == self.super_majority
            && pb.group_id == self.group_id
            && pb.db_version == self.db_version
            && pb.attestation_timeout == self.attestation_timeout
            && pb.simulated == self.simulated
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
    )
}

pub fn new_handshake(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
    expected_raft_config: &'static RaftConfig,
) -> Result<Handshake> {
    new_handshake_with_constants(
        mrenclave,
        attestation_msg,
        current_time,
        get_sw_advisories(mrenclave),
        expected_raft_config,
        SVR2_POSTQUANTUM_OVERRIDE
            .get(&mrenclave)
            .copied()
            .unwrap_or(HandshakeType::PostQuantum),
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

    use const_str::hex;

    use super::*;

    #[test]
    fn attest_svr2() {
        const HANDSHAKE_BYTES: &[u8] = include_bytes!("../tests/data/svr2handshakestart.data");
        let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1741649483);
        let mrenclave_bytes =
            hex!("38e01eff4fe357dc0b0e8ef7a44b4abc5489fbccba3a78780f3872c277f62bf3");
        new_handshake_with_constants(
            &mrenclave_bytes,
            HANDSHAKE_BYTES,
            current_time,
            &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
            &RaftConfig {
                min_voting_replicas: 3,
                max_voting_replicas: 5,
                super_majority: 0,
                group_id: 3565209795906488720,
                db_version: 2,
                attestation_timeout: 604800,
                simulated: false,
            },
            HandshakeType::PreQuantum,
        )
        .unwrap();
    }

    #[test]
    fn attest_svr2_bad_config() {
        const HANDSHAKE_BYTES: &[u8] = include_bytes!("../tests/data/svr2handshakestart.data");
        let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1741649483);
        let mrenclave_bytes =
            hex!("38e01eff4fe357dc0b0e8ef7a44b4abc5489fbccba3a78780f3872c277f62bf3");

        assert!(
            new_handshake_with_constants(
                &mrenclave_bytes,
                HANDSHAKE_BYTES,
                current_time,
                &[],
                &RaftConfig {
                    min_voting_replicas: 3,
                    max_voting_replicas: 5,
                    super_majority: 0,
                    group_id: 0, // wrong
                    db_version: 2,
                    attestation_timeout: 604800,
                    simulated: false,
                },
                HandshakeType::PreQuantum,
            )
            .is_err()
        );
    }

    fn matches(
        min_voting_replicas: u32,
        max_voting_replicas: u32,
        super_majority: u32,
        group_id: u64,
        db_version: i32,
        attestation_timeout: u32,
        simulated: bool,
        expected: &RaftConfig,
    ) -> bool {
        expected
            == &svr::RaftGroupConfig {
                min_voting_replicas,
                max_voting_replicas,
                super_majority,
                group_id,
                db_version,
                attestation_timeout,
                simulated,
            }
    }

    #[test]
    fn raft_config_matches() {
        let expected = RaftConfig {
            min_voting_replicas: 3,
            max_voting_replicas: 4,
            super_majority: 1,
            group_id: 12345,
            db_version: 2,
            attestation_timeout: 604800,
            simulated: false,
        };
        // valid
        assert!(matches(3, 4, 1, 12345, 2, 604800, false, &expected));

        // invalid
        assert!(!matches(2, 4, 1, 12345, 2, 604800, false, &expected));
        assert!(!matches(3, 3, 1, 12345, 2, 604800, false, &expected));
        assert!(!matches(3, 4, 0, 12345, 2, 604800, false, &expected));
        assert!(!matches(3, 4, 1, 54321, 2, 604800, false, &expected));
        assert!(!matches(3, 4, 1, 12345, 4, 604800, false, &expected));
        assert!(!matches(3, 4, 1, 12345, 2, 604801, false, &expected));
        assert!(!matches(3, 4, 1, 12345, 2, 604800, true, &expected));
    }
}
