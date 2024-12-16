//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Provides encryption / decryption of messages for an already established Noise protocol session.
//!
//! Once a noise handshake has already completed (using the constant pattern provided below),
//! messages can be encrypted into one or more noise transport messages for sending
//! with [ClientConnection::send]. Likewise a single received message consisting internally
//! of one or more noise transport messages can be decrypted with [ClientConnection::recv]

pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_SHA256";
pub const NOISE_PATTERN_HFS: &str = "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256";

pub(crate) const NOISE_HANDSHAKE_OVERHEAD: usize = 64 + /* post-quantum kyber1024: */ 1568;

pub(crate) const NOISE_TRANSPORT_PER_PACKET_MAX: usize = 65535;
pub(crate) const NOISE_TRANSPORT_PER_PAYLOAD_OVERHEAD: usize = 16;
pub(crate) const NOISE_TRANSPORT_PER_PAYLOAD_MAX: usize =
    NOISE_TRANSPORT_PER_PACKET_MAX - NOISE_TRANSPORT_PER_PAYLOAD_OVERHEAD;

#[derive(Debug)]
pub struct ClientConnection {
    pub handshake_hash: Vec<u8>,
    pub transport: snow::TransportState,
}

/// Result type for client connection.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// Noise error ({0})
    NoiseError(#[from] snow::Error),
}

impl ClientConnection {
    /// Wrap a plaintext message to be sent, returning the ciphertext.
    pub fn send(&mut self, plaintext_to_send: &[u8]) -> Result<Vec<u8>> {
        let max_ciphertext_size = plaintext_to_send.len()
            + plaintext_to_send
                .len()
                .div_ceil(NOISE_TRANSPORT_PER_PAYLOAD_MAX)
                * NOISE_TRANSPORT_PER_PAYLOAD_OVERHEAD;
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
