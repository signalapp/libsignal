//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use displaydoc::Display;
use prost::Message;
use std::convert::From;

use crate::client_connection;
use crate::dcap;
use crate::proto::cds2;
use crate::snow_resolver;

/// Error types for CDS2.
#[derive(Display, Debug)]
pub enum Error {
    /// failure to attest remote SGX enclave code: {0:?}
    DcapError(dcap::Error),
    /// failure to communicate on established Noise channel to CDS service: {0}
    NoiseError(client_connection::Error),
    /// failure to complete Noise handshake to CDS service: {0}
    NoiseHandshakeError(snow::Error),
    /// attestation data invalid: {reason}
    AttestationDataError { reason: String },
    /// invalid bridge state
    InvalidBridgeStateError,
}

const INVALID_MRENCLAVE: &str = "MREnclave value does not fit expected format";
const INVALID_CA_CERT: &str = "CA certificate does not fit expected format";
const INVALID_EVIDENCE: &str = "Evidence does not fit expected format";
const INVALID_ENDORSEMENT: &str = "Endorsement does not fit expected format";
const INVALID_CLAIMS: &str = "Claims do not fit expected format";

/// Result type for CDS2.
pub type Result<T> = std::result::Result<T, Error>;

impl From<snow::Error> for Error {
    fn from(e: snow::Error) -> Self {
        Error::NoiseHandshakeError(e)
    }
}

impl From<dcap::Error> for Error {
    fn from(err: dcap::Error) -> Error {
        Error::DcapError(err)
    }
}

impl From<client_connection::Error> for Error {
    fn from(err: client_connection::Error) -> Self {
        Error::NoiseError(err)
    }
}

impl From<prost::DecodeError> for Error {
    fn from(err: prost::DecodeError) -> Self {
        Error::AttestationDataError {
            reason: err.to_string(),
        }
    }
}

/// Wraps a connection to CDS2.
///
/// ```pseudocode
///   let websocket = ... open websocket ...
///   let attestation_msg = websocket.recv();
///   let mut client_conn_establishment = ClientConnectionEstablishment::new(
///       mrenclave, ca_cert, attestation_msg)?;
///   websocket.send(client_conn_establishment.initial_request());
///   let initial_response = websocket.recv(...);
///   let conn = client_conn_establishment.complete(initial_response);
/// ```
pub struct ClientConnectionEstablishment {
    handshake: snow::HandshakeState,
    initial_request: Vec<u8>,
}

impl ClientConnectionEstablishment {
    pub fn new(
        mrenclave: &[u8],
        ca_cert: &[u8],
        attestation_msg: &[u8],
        earliest_valid_time: std::time::SystemTime,
    ) -> Result<Self> {
        if mrenclave.is_empty() {
            return Err(Error::AttestationDataError {
                reason: String::from(INVALID_MRENCLAVE),
            });
        }
        if ca_cert.is_empty() {
            return Err(Error::AttestationDataError {
                reason: String::from(INVALID_CA_CERT),
            });
        }

        // Deserialize attestation handshake start.
        let handshake_start = cds2::ClientHandshakeStart::decode(attestation_msg)?;

        if handshake_start.evidence.is_empty() {
            return Err(Error::AttestationDataError {
                reason: String::from(INVALID_EVIDENCE),
            });
        }
        if handshake_start.endorsement.is_empty() {
            return Err(Error::AttestationDataError {
                reason: String::from(INVALID_ENDORSEMENT),
            });
        }

        // DCAP.
        let claims = dcap::NOT_FOR_PRODUCTION_verify_remote_attestation(
            &handshake_start.evidence,
            &handshake_start.endorsement,
            mrenclave,
            ca_cert,
            earliest_valid_time,
        )?;

        if claims.len() != 1 {
            return Err(Error::AttestationDataError {
                reason: String::from(INVALID_CLAIMS),
            });
        }

        let unwrapped_public_key = claims.get("pk").ok_or(Error::AttestationDataError {
            reason: String::from(INVALID_CLAIMS),
        })?;

        let mut handshake = snow::Builder::with_resolver(
            client_connection::NOISE_PATTERN.parse().expect("valid"),
            Box::new(snow_resolver::Resolver),
        )
        .remote_public_key(unwrapped_public_key)
        .build_initiator()?;
        let mut initial_request = vec![0u8; client_connection::NOISE_HANDSHAKE_OVERHEAD];
        // We send an empty message, but the roundtrip to the server and back is still required
        // in order to complete the noise handshake. If we needed some initial payload we could
        // add it here in future.
        let size = handshake.write_message(&[], &mut initial_request)?;
        initial_request.truncate(size);
        Ok(Self {
            handshake,
            initial_request,
        })
    }

    /// Initial message from client for noise handshake.
    pub fn initial_request(&self) -> &[u8] {
        &self.initial_request
    }

    /// Completes client connection initiation, returns a valid client connection.
    pub fn complete(
        mut self,
        initial_received: &[u8],
    ) -> Result<client_connection::ClientConnection> {
        self.handshake.read_message(initial_received, &mut [])?;
        let transport = self.handshake.into_transport_mode()?;
        log::info!("Successfully completed CDS2 connection");
        Ok(client_connection::ClientConnection { transport })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use super::*;

    fn read_test_file(path: &str) -> Vec<u8> {
        fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).expect("Failed to read file")
    }

    fn handshake_from_tests_data() -> Result<ClientConnectionEstablishment> {
        // Read test data files, de-hex-stringing as necessary.
        let trusted_ca_cert = read_test_file("tests/data/trustedRootCaCert.pem");
        let evidence_bytes = read_test_file("tests/data/cds2_test.evidence");
        let endorsement_bytes = read_test_file("tests/data/cds2_test.endorsements");
        let mut mrenclave_bytes = vec![0u8; 32];
        let mrenclave_str = read_test_file("tests/data/cds2_test.mrenclave");
        hex::decode_to_slice(mrenclave_str, &mut mrenclave_bytes)
            .expect("Failed to decode mrenclave from hex string");

        let attestation_msg = cds2::ClientHandshakeStart {
            evidence: evidence_bytes,
            endorsement: endorsement_bytes,
            ..Default::default()
        };
        let attestation_vec = attestation_msg.encode_to_vec();
        let earliest_valid_time = SystemTime::now() - Duration::from_secs(60 * 60 * 24);
        ClientConnectionEstablishment::new(
            &mrenclave_bytes,
            &trusted_ca_cert,
            &attestation_vec,
            earliest_valid_time,
        )
    }

    #[test]
    fn test_cds2_happy_path() -> Result<()> {
        // Spin up a handshake for the server-side.
        let mut private_key = [0u8; 32];
        let private_key_hex = read_test_file("tests/data/cds2_test.privatekey");
        hex::decode_to_slice(private_key_hex, &mut private_key)
            .expect("Failed to decode private key from hex string");

        // Start the server with a known private key (K of NK).
        let mut server_hs = snow::Builder::new(client_connection::NOISE_PATTERN.parse()?)
            .local_private_key(&private_key)
            .build_responder()?;

        // Spin up the client connection establishment.
        let establishment = handshake_from_tests_data()?;

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
    fn test_cds2_mismatched_keys() -> Result<()> {
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
        let establishment = handshake_from_tests_data()?;

        // Establishment message fails for key mismatch.
        let mut payload = vec![0u8; 32];
        let read_size = server_hs.read_message(establishment.initial_request(), &mut payload);
        assert!(read_size.is_err());
        assert!(matches!(read_size.err().unwrap(), snow::Error::Decrypt));

        Ok(())
    }

    #[test]
    fn test_cds2_invalid_private_key() -> Result<()> {
        // Spin up a handshake for the server-side.
        // This key is just totally invalid.
        let bad_private_key: [u8; 32] = [1u8; 32];
        // Start server with random key that does not match our invalid private key.
        let mut server_hs = snow::Builder::new(client_connection::NOISE_PATTERN.parse()?)
            .local_private_key(&bad_private_key)
            .build_responder()?;

        // Spin up the client connection establishment.
        let establishment = handshake_from_tests_data()?;

        // Establishment message fails for key mismatch.
        let mut payload = vec![0u8; 32];
        let read_size = server_hs.read_message(establishment.initial_request(), &mut payload);
        assert!(read_size.is_err());
        assert!(matches!(read_size.err().unwrap(), snow::Error::Decrypt));

        Ok(())
    }
}
