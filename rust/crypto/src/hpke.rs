//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hpke_rs::prelude::*;

mod provider;

pub use hpke_rs::HpkeError;

/// A type byte marking one of Signal's chosen instantiations of HPKE.
#[derive(Clone, Copy, PartialEq, Eq, Debug, derive_more::TryFrom)]
#[repr(u8)]
#[allow(non_camel_case_types)]
#[try_from(repr)]
pub enum SignalHpkeCiphertextType {
    Base_X25519_HkdfSha256_Aes256Gcm = 1,
}

impl From<SignalHpkeCiphertextType> for u8 {
    fn from(value: SignalHpkeCiphertextType) -> Self {
        value as Self
    }
}

impl SignalHpkeCiphertextType {
    fn set_up(self) -> Hpke<provider::CryptoProvider> {
        Hpke::new(
            self.mode(),
            self.kem_algorithm(),
            self.kdf_algorithm(),
            self.aead_algorithm(),
        )
    }

    fn mode(self) -> HpkeMode {
        match self {
            SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm => HpkeMode::Base,
        }
    }

    fn kem_algorithm(self) -> hpke_types::KemAlgorithm {
        match self {
            SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm => {
                hpke_types::KemAlgorithm::DhKem25519
            }
        }
    }

    fn kdf_algorithm(self) -> hpke_types::KdfAlgorithm {
        match self {
            SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm => {
                hpke_types::KdfAlgorithm::HkdfSha256
            }
        }
    }

    fn aead_algorithm(self) -> hpke_types::AeadAlgorithm {
        match self {
            SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm => {
                hpke_types::AeadAlgorithm::Aes256Gcm
            }
        }
    }
}

/// A thoroughly stripped-down version of [HPKE][] that only supports the "base" mode
/// (unauthenticated, no pre-shared key).
///
/// Additionally hardcodes the KDF as HKDF-SHA-256 and the AEAD as AES-256-GCM, as used elsewhere in
/// libsignal.
///
/// See also [SimpleHpkeReceiver].
///
/// [HPKE]: https://www.rfc-editor.org/rfc/rfc9180.html
pub trait SimpleHpkeSender {
    fn seal(&self, info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError>;
}

impl SimpleHpkeSender for libsignal_core::curve::PublicKey {
    fn seal(&self, info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let ciphertext_type = match self.key_type() {
            libsignal_core::curve::KeyType::Djb => {
                SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm
            }
        };

        let hpke_key = HpkePublicKey::from(self.public_key_bytes());
        let (encapsulated_secret, mut ciphertext) = ciphertext_type
            .set_up()
            .seal(&hpke_key, info, aad, plaintext, None, None, None)?;
        debug_assert_eq!(
            encapsulated_secret.len(),
            ciphertext_type.kem_algorithm().shared_secret_len()
        );

        // Insert the type byte and the encapsulated secret at the front of the ciphertext. We do
        // this by mutating the ciphertext rather than creating a new Vec (or appending to the
        // secret) because we have the best chance of the ciphertext Vec already having extra room
        // in the buffer, in which case we're just moving bytes around with no new allocations. If
        // not, this should fall back to effectively creating a new buffer and copying all three
        // parts into it.
        ciphertext.splice(
            0..0,
            [ciphertext_type.into()]
                .into_iter()
                .chain(encapsulated_secret),
        );

        Ok(ciphertext)
    }
}

/// A thoroughly stripped-down version of [HPKE][] that only supports the "base" mode
/// (unauthenticated, no pre-shared key).
///
/// Additionally hardcodes the KDF as HKDF-SHA-256 and the AEAD as AES-256-GCM, as used elsewhere in
/// libsignal.
///
/// See also [SimpleHpkeReceiver].
///
/// [HPKE]: https://www.rfc-editor.org/rfc/rfc9180.html
pub trait SimpleHpkeReceiver {
    fn open(&self, info: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError>;
}

impl SimpleHpkeReceiver for libsignal_core::curve::PrivateKey {
    fn open(&self, info: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let (ciphertext_type, ciphertext) = ciphertext
            .split_at_checked(1)
            .ok_or(HpkeError::InvalidInput)?;
        let ciphertext_type = ciphertext_type[0]
            .try_into()
            .map_err(|_| HpkeError::UnknownMode)?;

        // Check for a ciphertext using a non-Curve25519 key.
        // This code will need to be updated if there are other key types or ciphertext types in the future.
        match (ciphertext_type, self.key_type()) {
            (
                SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm,
                libsignal_core::curve::KeyType::Djb,
            ) => {}
        }

        let (encapsulated_secret, ciphertext) = ciphertext
            .split_at_checked(ciphertext_type.kem_algorithm().shared_secret_len())
            .ok_or(HpkeError::InvalidInput)?;

        let hpke_key = HpkePrivateKey::from(self.serialize());
        ciphertext_type.set_up().open(
            encapsulated_secret,
            &hpke_key,
            info,
            aad,
            ciphertext,
            None,
            None,
            None,
        )
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use libsignal_core::curve::KeyPair;

    use super::*;

    #[test]
    fn basic() {
        let key_pair = KeyPair::generate(&mut rand::rng());
        let info = b"info";
        let aad = b"extra";
        let contents = b"message";

        let ciphertext = key_pair
            .public_key
            .seal(info, aad, contents)
            .expect("can seal");
        let unsealed = key_pair
            .private_key
            .open(info, aad, &ciphertext)
            .expect("can open");
        assert_eq!(&contents[..], unsealed);

        let another_key = KeyPair::generate(&mut rand::rng());
        assert_matches!(
            another_key
                .private_key
                .open(info, aad, &ciphertext)
                .expect_err("should fail"),
            HpkeError::OpenError
        );
    }
}
