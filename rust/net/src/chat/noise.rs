//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod encrypted_stream;
pub use encrypted_stream::{Authorization, ConnectMeta, EncryptedStream};
use libsignal_net_infra::noise::{
    HandshakeAuthKind, NoiseHandshake, EPHEMERAL_KEY_LEN, STATIC_KEY_LEN,
};

const STATIC_KEY_AEAD_TAG_LEN: usize = 16;

pub enum HandshakeAuth<'k> {
    IK {
        server_public_key: &'k [u8; STATIC_KEY_LEN],
        client_private_key: &'k [u8; EPHEMERAL_KEY_LEN],
    },
    NK {
        server_public_key: &'k [u8; STATIC_KEY_LEN],
    },
}

impl NoiseHandshake for HandshakeAuth<'_> {
    fn handshake_message_len(&self) -> usize {
        match self {
            Self::IK { .. } => EPHEMERAL_KEY_LEN + STATIC_KEY_LEN + STATIC_KEY_AEAD_TAG_LEN,
            Self::NK { .. } => EPHEMERAL_KEY_LEN,
        }
    }
    fn into_handshake_state(self) -> snow::HandshakeState {
        let resolver = Box::new(attest::snow_resolver::Resolver);
        match self {
            HandshakeAuth::IK {
                server_public_key,
                client_private_key,
            } => snow::Builder::with_resolver(IK_NOISE_PATTERN.parse().unwrap(), resolver)
                .remote_public_key(server_public_key)
                .local_private_key(client_private_key),
            HandshakeAuth::NK { server_public_key } => {
                snow::Builder::with_resolver(NK_NOISE_PATTERN.parse().unwrap(), resolver)
                    .remote_public_key(server_public_key)
            }
        }
        .build_initiator()
        .expect("building handshake failed")
    }
    fn auth_kind(&self) -> HandshakeAuthKind {
        match self {
            HandshakeAuth::IK { .. } => HandshakeAuthKind::IK,
            HandshakeAuth::NK { .. } => HandshakeAuthKind::NK,
        }
    }
}

pub(crate) const IK_NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";
pub(crate) const NK_NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2b";
