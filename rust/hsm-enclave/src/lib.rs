//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Support logic for connecting to an HSM-backed enclave.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use log::*;
use std::convert::From;
use std::fmt;

mod snow_resolver;

/// Error types for HSM enclave.
#[derive(Debug)]
pub enum Error {
    /// Failure to connect to a trusted HSM.
    HSMCommunicationError(snow::Error),
    /// Failure to connect to trusted code on the given HSM.
    TrustedCodeError,
    /// Invalid public key provided (used in bridging)
    InvalidPublicKeyError,
    /// Invalid code hash provided (used in bridging)
    InvalidCodeHashError,
    /// Invalid state of wrapper (used in bridging)
    InvalidBridgeStateError,
}

/// Result type for HSM enclave.
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::HSMCommunicationError(n) => write!(f, "Error in Noise protocol ({})", n),
            Error::TrustedCodeError => {
                write!(f, "Trusted HSM process does not match trusted code hash")
            }
            Error::InvalidPublicKeyError => {
                write!(f, "Invalid public key, must be {} bytes", PUB_KEY_SIZE)
            }
            Error::InvalidCodeHashError => {
                write!(
                    f,
                    "Invalid code hashes, must be >0 hashes, each exactly {} bytes",
                    CODE_HASH_SIZE
                )
            }
            Error::InvalidBridgeStateError => {
                write!(f, "Invalid bridge state")
            }
        }
    }
}

impl From<snow::Error> for Error {
    fn from(e: snow::Error) -> Self {
        Error::HSMCommunicationError(e)
    }
}

/// Wraps a connection handshake to an HSM-resident enclave.
///
/// ```pseudocode
///   let mut client_conn_establishment = ClientConnectionEstablishment::new(...)?;
///   let websocket = ... open websocket ...
///   websocket.send(client_conn_establishment.initial_request());
///   let initial_response = websocket.recv(...);
///   let conn = client_conn_establishment.complete(initial_response)?;
/// ```
pub struct ClientConnectionEstablishment {
    hs: snow::HandshakeState,
    initial_message: Vec<u8>,
    trusted_code_hashes: Vec<[u8; CODE_HASH_SIZE]>,
}

const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_SHA256";
const NOISE_HANDSHAKE_OVERHEAD: usize = 64; // TODO: this could be more exact

/// The size in bytes of a code hash.
pub const CODE_HASH_SIZE: usize = 32;
/// The size in bytes of a public key.
pub const PUB_KEY_SIZE: usize = 32;

impl ClientConnectionEstablishment {
    /// Creates a new client connection establishment.
    pub fn new(
        trusted_public_key: [u8; PUB_KEY_SIZE],
        trusted_code_hashes: Vec<[u8; CODE_HASH_SIZE]>,
    ) -> Result<Self> {
        let mut hs = snow::Builder::with_resolver(
            NOISE_PATTERN.parse().expect("valid"),
            Box::new(snow_resolver::Resolver),
        )
        .remote_public_key(&trusted_public_key[..])
        .build_initiator()?;
        let payload = trusted_code_hashes.concat();
        let mut initial_message = vec![0u8; NOISE_HANDSHAKE_OVERHEAD + payload.len()];
        let size = hs.write_message(&payload, &mut initial_message)?;
        initial_message.truncate(size);
        Ok(Self {
            hs,
            initial_message,
            trusted_code_hashes,
        })
    }

    /// Initial message to send to server to establish connection.
    pub fn initial_request(&self) -> &[u8] {
        &self.initial_message
    }

    /// Completes client connection initiation, returns a valid client connection.
    pub fn complete(mut self, initial_received: &[u8]) -> Result<ClientConnection> {
        let mut received_hash = [0u8; CODE_HASH_SIZE];
        let size = self.hs.read_message(initial_received, &mut received_hash)?;
        if size != received_hash.len() {
            return Err(Error::TrustedCodeError);
        }
        if !self.trusted_code_hashes.contains(&received_hash) {
            return Err(Error::TrustedCodeError);
        }
        let transport = self.hs.into_transport_mode()?;
        log::info!(
            "Successfully completed HSM-enclave connection to codehash {:x?}",
            received_hash
        );
        Ok(ClientConnection { transport })
    }
}

/// Wraps an established connection to an HSM-resident enclave.
///
/// ```pseudocode
///   let conn = client_connection_establishment.complete(...)?;
///
///   // any number of sends:
///   let plaintext_to_send: &[u8] = ...;
///   let encrypted_to_send: Vec<u8> = conn.send(plaintext_to_send)?;
///   websocket.send(&encrypted_to_send)?;
///
///   // and receives:
///   let encrypted_received = websocket.recv(...)?;
///   let plaintext_received: Vec<u8> = conn.recv(encrypted_received)?;
/// ```
pub struct ClientConnection {
    transport: snow::TransportState,
}

const NOISE_TRANSPORT_PER_PACKET_MAX: usize = 65535;
const NOISE_TRANSPORT_PER_PAYLOAD_OVERHEAD: usize = 16;
const NOISE_TRANSPORT_PER_PAYLOAD_MAX: usize =
    NOISE_TRANSPORT_PER_PACKET_MAX - NOISE_TRANSPORT_PER_PAYLOAD_OVERHEAD;

impl ClientConnection {
    /// Wrap a plaintext message to be sent, returning the ciphertext.
    pub fn send(&mut self, plaintext_to_send: &[u8]) -> Result<Vec<u8>> {
        let max_ciphertext_size = plaintext_to_send.len()
            + (1 + plaintext_to_send.len() / NOISE_TRANSPORT_PER_PAYLOAD_MAX)
                * NOISE_HANDSHAKE_OVERHEAD;
        let mut ciphertext = vec![0u8; max_ciphertext_size];
        let mut total_size = 0;
        for chunk in plaintext_to_send.chunks(NOISE_TRANSPORT_PER_PAYLOAD_MAX) {
            total_size += self
                .transport
                .write_message(chunk, &mut ciphertext[total_size..])?;
        }
        ciphertext.truncate(total_size);
        Ok(ciphertext)
    }

    /// Unwrap a ciphertext message that's been received, returning the plaintext.
    pub fn recv(&mut self, received_ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut received_plaintext: Vec<u8> = vec![0u8; received_ciphertext.len()];
        let mut total_size = 0;
        for chunk in received_ciphertext.chunks(NOISE_TRANSPORT_PER_PACKET_MAX) {
            total_size += self
                .transport
                .read_message(chunk, &mut received_plaintext[total_size..])?;
        }
        received_plaintext.truncate(total_size);
        Ok(received_plaintext)
    }
}
