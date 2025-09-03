//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

use zerocopy::{FromBytes, IntoBytes, KnownLayout};

use crate::proto::storage::session_structure;
use crate::{PrivateKey, PublicKey, Result, crypto};

pub(crate) enum MessageKeyGenerator {
    Keys(MessageKeys),
    Seed((Vec<u8>, u32)),
}

impl MessageKeyGenerator {
    pub(crate) fn new_from_seed(seed: &[u8], counter: u32) -> Self {
        Self::Seed((seed.to_vec(), counter))
    }
    pub(crate) fn generate_keys(self, pqr_key: spqr::MessageKey) -> MessageKeys {
        match self {
            Self::Seed((seed, counter)) => {
                MessageKeys::derive_keys(&seed, pqr_key.as_deref(), counter)
            }
            Self::Keys(k) => {
                // PQR keys should only be set for newer sessions, and in
                // newer sessions there should be only seed-based generators.
                assert!(pqr_key.is_none());
                k
            }
        }
    }
    pub(crate) fn into_pb(self) -> session_structure::chain::MessageKey {
        match self {
            Self::Keys(k) => session_structure::chain::MessageKey {
                cipher_key: k.cipher_key().to_vec(),
                mac_key: k.mac_key().to_vec(),
                iv: k.iv().to_vec(),
                index: k.counter(),
                seed: vec![],
            },
            Self::Seed((seed, counter)) => session_structure::chain::MessageKey {
                cipher_key: vec![],
                mac_key: vec![],
                iv: vec![],
                index: counter,
                seed,
            },
        }
    }
    pub(crate) fn from_pb(
        pb: session_structure::chain::MessageKey,
    ) -> std::result::Result<Self, &'static str> {
        Ok(if pb.seed.is_empty() {
            Self::Keys(MessageKeys {
                cipher_key: pb
                    .cipher_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid message cipher key")?,
                mac_key: pb
                    .mac_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid message MAC key")?,
                iv: pb
                    .iv
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid message IV")?,
                counter: pb.index,
            })
        } else {
            Self::Seed((pb.seed, pb.index))
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MessageKeys {
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
    iv: [u8; 16],
    counter: u32,
}

impl MessageKeys {
    pub(crate) fn derive_keys(
        input_key_material: &[u8],
        optional_salt: Option<&[u8]>,
        counter: u32,
    ) -> Self {
        #[derive(Default, KnownLayout, IntoBytes, FromBytes)]
        #[repr(C, packed)]
        struct DerivedSecretBytes([u8; 32], [u8; 32], [u8; 16]);
        let mut okm = DerivedSecretBytes::default();

        hkdf::Hkdf::<sha2::Sha256>::new(optional_salt, input_key_material)
            .expand(b"WhisperMessageKeys", okm.as_mut_bytes())
            .expect("valid output length");

        let DerivedSecretBytes(cipher_key, mac_key, iv) = okm;

        MessageKeys {
            cipher_key,
            mac_key,
            iv,
            counter,
        }
    }

    #[inline]
    pub(crate) fn cipher_key(&self) -> &[u8; 32] {
        &self.cipher_key
    }

    #[inline]
    pub(crate) fn mac_key(&self) -> &[u8; 32] {
        &self.mac_key
    }

    #[inline]
    pub(crate) fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    #[inline]
    pub(crate) fn counter(&self) -> u32 {
        self.counter
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ChainKey {
    key: [u8; 32],
    index: u32,
}

impl ChainKey {
    const MESSAGE_KEY_SEED: [u8; 1] = [0x01u8];
    const CHAIN_KEY_SEED: [u8; 1] = [0x02u8];

    pub(crate) fn new(key: [u8; 32], index: u32) -> Self {
        Self { key, index }
    }

    #[inline]
    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }

    #[inline]
    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    pub(crate) fn next_chain_key(&self) -> Self {
        Self {
            key: self.calculate_base_material(Self::CHAIN_KEY_SEED),
            index: self.index + 1,
        }
    }

    pub(crate) fn message_keys(&self) -> MessageKeyGenerator {
        MessageKeyGenerator::new_from_seed(
            &self.calculate_base_material(Self::MESSAGE_KEY_SEED),
            self.index,
        )
    }

    fn calculate_base_material(&self, seed: [u8; 1]) -> [u8; 32] {
        crypto::hmac_sha256(&self.key, &seed)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RootKey {
    key: [u8; 32],
}

impl RootKey {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub(crate) fn create_chain(
        self,
        their_ratchet_key: &PublicKey,
        our_ratchet_key: &PrivateKey,
    ) -> Result<(RootKey, ChainKey)> {
        let shared_secret = our_ratchet_key.calculate_agreement(their_ratchet_key)?;
        #[derive(Default, KnownLayout, IntoBytes, FromBytes)]
        #[repr(C, packed)]
        struct DerivedSecretBytes([u8; 32], [u8; 32]);
        let mut derived_secret_bytes = DerivedSecretBytes::default();

        hkdf::Hkdf::<sha2::Sha256>::new(Some(&self.key), &shared_secret)
            .expand(b"WhisperRatchet", derived_secret_bytes.as_mut_bytes())
            .expect("valid output length");

        let DerivedSecretBytes(root_key, chain_key) = derived_secret_bytes;

        Ok((
            RootKey { key: root_key },
            ChainKey {
                key: chain_key,
                index: 0,
            },
        ))
    }
}

impl fmt::Display for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_key_derivation() -> Result<()> {
        let seed = [
            0x8au8, 0xb7, 0x2d, 0x6f, 0x4c, 0xc5, 0xac, 0x0d, 0x38, 0x7e, 0xaf, 0x46, 0x33, 0x78,
            0xdd, 0xb2, 0x8e, 0xdd, 0x07, 0x38, 0x5b, 0x1c, 0xb0, 0x12, 0x50, 0xc7, 0x15, 0x98,
            0x2e, 0x7a, 0xd4, 0x8f,
        ];
        let message_key = [
            0xbfu8, 0x51, 0xe9, 0xd7, 0x5e, 0x0e, 0x31, 0x03, 0x10, 0x51, 0xf8, 0x2a, 0x24, 0x91,
            0xff, 0xc0, 0x84, 0xfa, 0x29, 0x8b, 0x77, 0x93, 0xbd, 0x9d, 0xb6, 0x20, 0x05, 0x6f,
            0xeb, 0xf4, 0x52, 0x17,
        ];
        let mac_key = [
            0xc6u8, 0xc7, 0x7d, 0x6a, 0x73, 0xa3, 0x54, 0x33, 0x7a, 0x56, 0x43, 0x5e, 0x34, 0x60,
            0x7d, 0xfe, 0x48, 0xe3, 0xac, 0xe1, 0x4e, 0x77, 0x31, 0x4d, 0xc6, 0xab, 0xc1, 0x72,
            0xe7, 0xa7, 0x03, 0x0b,
        ];
        let next_chain_key = [
            0x28u8, 0xe8, 0xf8, 0xfe, 0xe5, 0x4b, 0x80, 0x1e, 0xef, 0x7c, 0x5c, 0xfb, 0x2f, 0x17,
            0xf3, 0x2c, 0x7b, 0x33, 0x44, 0x85, 0xbb, 0xb7, 0x0f, 0xac, 0x6e, 0xc1, 0x03, 0x42,
            0xa2, 0x46, 0xd1, 0x5d,
        ];

        let chain_key = ChainKey::new(seed, 0);
        assert_eq!(&seed, chain_key.key());
        assert_eq!(
            &message_key,
            chain_key.message_keys().generate_keys(None).cipher_key()
        );
        assert_eq!(
            &mac_key,
            chain_key.message_keys().generate_keys(None).mac_key()
        );
        assert_eq!(&next_chain_key, chain_key.next_chain_key().key());
        assert_eq!(0, chain_key.index());
        assert_eq!(0, chain_key.message_keys().generate_keys(None).counter());
        assert_eq!(1, chain_key.next_chain_key().index());
        assert_eq!(
            1,
            chain_key
                .next_chain_key()
                .message_keys()
                .generate_keys(None)
                .counter()
        );
        Ok(())
    }
}
