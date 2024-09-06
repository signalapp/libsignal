//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Supports creating a noise encrypted message channel to a remote SGX enclave.
//!
//! A caller begins with some message-oriented connection (e.g. a websocket) to a SGX
//! enclave service. Once the remote enclave's attestation is retrieved, they may use
//! [Handshake] to construct a noise encrypted session with the enclave. The attestation
//! must contain a custom claim with the key name "pk" that represents the enclave's
//! public key.
use std::time::Duration;

use crate::dcap::{self, MREnclave};
use crate::enclave::{Claims, Error, Handshake, HandshakeType, Result, UnvalidatedHandshake};

const INVALID_EVIDENCE: &str = "Evidence does not fit expected format";
const INVALID_ENDORSEMENT: &str = "Endorsement does not fit expected format";
const INVALID_MRENCLAVE: &str = "MREnclave value does not fit expected format";

/// How much to offset when checking for time-based validity checks
/// to adjust for clock skew on clients
const SKEW_ADJUSTMENT: Duration = Duration::from_secs(24 * 60 * 60);

impl Handshake {
    pub(crate) fn for_sgx(
        mrenclave: &[u8],
        evidence: &[u8],
        endorsements: &[u8],
        acceptable_sw_advisories: &[&str],
        current_time: std::time::SystemTime,
        handshake_type: HandshakeType,
    ) -> Result<UnvalidatedHandshake> {
        if evidence.is_empty() {
            return Err(Error::AttestationDataError {
                reason: String::from(INVALID_EVIDENCE),
            });
        }
        if endorsements.is_empty() {
            return Err(Error::AttestationDataError {
                reason: String::from(INVALID_ENDORSEMENT),
            });
        }

        let mrenclave: MREnclave =
            mrenclave
                .try_into()
                .map_err(|_| Error::AttestationDataError {
                    reason: String::from(INVALID_MRENCLAVE),
                })?;

        // verify the remote attestation and extract the custom claims
        let claims = dcap::verify_remote_attestation(
            evidence,
            endorsements,
            &mrenclave,
            acceptable_sw_advisories,
            current_time + SKEW_ADJUSTMENT,
        )?;

        Self::with_claims(Claims::from_custom_claims(claims)?, handshake_type)
    }
}

pub mod testutil {
    use std::time::{Duration, SystemTime};

    use super::*;

    pub const EVIDENCE_BYTES: &[u8] = include_bytes!("../tests/data/cds2_test.evidence");
    pub const ENDORSEMENT_BYTES: &[u8] = include_bytes!("../tests/data/cds2_test.endorsements");

    pub fn mrenclave_bytes() -> Vec<u8> {
        let mut mrenclave_bytes = vec![0u8; 32];
        let mrenclave_str = include_bytes!("../tests/data/cds2_test.mrenclave");
        hex::decode_to_slice(mrenclave_str, &mut mrenclave_bytes)
            .expect("Failed to decode mrenclave from hex string");
        mrenclave_bytes
    }

    pub fn private_key() -> [u8; 32] {
        let mut private_key = [0; 32];
        let private_key_hex = include_bytes!("../tests/data/cds2_test.privatekey");
        hex::decode_to_slice(private_key_hex, &mut private_key)
            .expect("Failed to decode private key from hex string");
        private_key
    }

    pub fn valid_start() -> SystemTime {
        // the test pck crl starts being valid at Jun 21 21:15:11 2022 GMT
        SystemTime::UNIX_EPOCH + Duration::from_secs(1655846111)
    }

    pub fn handshake_from_tests_data() -> Result<Handshake> {
        // Read test data files, de-hex-stringing as necessary.
        let mrenclave_bytes = mrenclave_bytes();
        let current_time = SystemTime::UNIX_EPOCH + Duration::from_millis(1655857680000);
        Ok(Handshake::for_sgx(
            &mrenclave_bytes,
            EVIDENCE_BYTES,
            ENDORSEMENT_BYTES,
            &[],
            current_time,
            HandshakeType::PreQuantum,
        )?
        .skip_raft_validation())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::client_connection;

    #[test]
    fn test_clock_skew() {
        let mrenclave_bytes = testutil::mrenclave_bytes();

        let test = |time: SystemTime, expect_success: bool| {
            let result = Handshake::for_sgx(
                &mrenclave_bytes,
                testutil::EVIDENCE_BYTES,
                testutil::ENDORSEMENT_BYTES,
                &[],
                time,
                HandshakeType::PreQuantum,
            );
            assert_eq!(result.is_ok(), expect_success);
        };

        let valid_start = testutil::valid_start();

        // and expires 30 days later on Jul 21 21:15:11 2022 GMT
        let valid_end = valid_start + Duration::from_secs(30 * 24 * 60 * 60);

        // a request from slightly earlier should succeed
        test(valid_start - SKEW_ADJUSTMENT, true);

        // a request from more than the skew before should fail
        test(
            valid_start - SKEW_ADJUSTMENT - Duration::from_secs(1),
            false,
        );

        // an request within a day of expiration will fail from the skew adjustment
        test(valid_end - SKEW_ADJUSTMENT, false);

        // earlier than that is fine
        test(valid_end - SKEW_ADJUSTMENT - Duration::from_secs(1), true);
    }

    #[test]
    fn test_happy_path() -> Result<()> {
        // Spin up a handshake for the server-side.
        let private_key = testutil::private_key();
        // Start the server with a known private key (K of NK).
        let mut server_hs = snow::Builder::new(client_connection::NOISE_PATTERN.parse()?)
            .local_private_key(&private_key)
            .build_responder()?;

        // Spin up the client connection establishment.
        let establishment = testutil::handshake_from_tests_data()?;

        // Give the establishment message to the server.
        let read_size = server_hs.read_message(establishment.initial_request(), &mut [])?;
        assert_eq!(read_size, 0);

        // Send message back to client, finish handshake.
        let mut message = vec![0u8; 48];
        let write_size = server_hs.write_message(&[], &mut message)?;
        assert_eq!(write_size, 48);
        assert!(server_hs.is_handshake_finished());
        let mut server_transport = server_hs.into_transport_mode()?;

        // This should complete our connection establishment, now.
        let mut conn = establishment.complete(&message)?;

        // Send message server to client.
        let mut svr_cli_message = vec![0u8; 19]; // size=3 + overhead=16
        let svr_cli_write_size =
            server_transport.write_message(&[7, 8, 9], &mut svr_cli_message)?;
        assert_eq!(svr_cli_write_size, 19);
        assert_eq!([7, 8, 9], conn.recv(&svr_cli_message)?.as_slice());

        // Send message client to server.
        let cli_svr_message = conn.send(&[0xa, 0xb, 0xc])?;
        let mut cli_svr_payload = vec![0u8; 3];
        let cli_svr_read_size =
            server_transport.read_message(&cli_svr_message, &mut cli_svr_payload)?;
        assert_eq!(cli_svr_read_size, 3);
        assert_eq!([0xAu8, 0xBu8, 0xCu8], cli_svr_payload.as_slice());

        Ok(())
    }

    #[test]
    fn test_mismatched_keys() -> Result<()> {
        // Spin up a handshake for the server-side.
        // This key is valid, but not matching.
        let mut bad_private_key: [u8; 32] = [1u8; 32];
        bad_private_key[0] &= 0xF8;
        bad_private_key[31] = (bad_private_key[31] & 0x7f) | 0x40;
        // Start server with random key that does not match our private key.
        let mut server_hs = snow::Builder::new(client_connection::NOISE_PATTERN.parse()?)
            .local_private_key(&bad_private_key)
            .build_responder()?;

        // Spin up the client connection establishment.
        let establishment = testutil::handshake_from_tests_data()?;

        // Establishment message fails for key mismatch.
        let mut payload = vec![0u8; 32];
        let read_size = server_hs.read_message(establishment.initial_request(), &mut payload);
        assert!(read_size.is_err());
        assert!(matches!(read_size.err().unwrap(), snow::Error::Decrypt));

        Ok(())
    }

    #[test]
    fn test_invalid_private_key() -> Result<()> {
        // Spin up a handshake for the server-side.
        // This key is just totally invalid.
        let bad_private_key: [u8; 32] = [1u8; 32];
        // Start server with random key that does not match our invalid private key.
        let mut server_hs = snow::Builder::new(client_connection::NOISE_PATTERN.parse()?)
            .local_private_key(&bad_private_key)
            .build_responder()?;

        // Spin up the client connection establishment.
        let establishment = testutil::handshake_from_tests_data()?;

        // Establishment message fails for key mismatch.
        let mut payload = vec![0u8; 32];
        let read_size = server_hs.read_message(establishment.initial_request(), &mut payload);
        assert!(read_size.is_err());
        assert!(matches!(read_size.err().unwrap(), snow::Error::Decrypt));

        Ok(())
    }
}
