//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub(crate) mod curve25519;

use std::cmp::Ordering;
use std::fmt;

use arrayref::array_ref;
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar, Scalar};
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

use crate::{Result, SignalProtocolError};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyType {
    Djb,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl KeyType {
    fn value(&self) -> u8 {
        match &self {
            KeyType::Djb => 0x05u8,
        }
    }
}

impl TryFrom<u8> for KeyType {
    type Error = SignalProtocolError;

    fn try_from(x: u8) -> Result<Self> {
        match x {
            0x05u8 => Ok(KeyType::Djb),
            t => Err(SignalProtocolError::BadKeyType(t)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PublicKeyData {
    DjbPublicKey([u8; curve25519::PUBLIC_KEY_LENGTH]),
}

#[derive(Clone, Copy, Eq)]
pub struct PublicKey {
    key: PublicKeyData,
}

impl PublicKey {
    fn new(key: PublicKeyData) -> Self {
        Self { key }
    }

    pub fn deserialize(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0])?;
        match key_type {
            KeyType::Djb => {
                // We allow trailing data after the public key (why?)
                if value.len() < curve25519::PUBLIC_KEY_LENGTH + 1 {
                    return Err(SignalProtocolError::BadKeyLength(KeyType::Djb, value.len()));
                }
                let mut key = [0u8; curve25519::PUBLIC_KEY_LENGTH];
                key.copy_from_slice(&value[1..][..curve25519::PUBLIC_KEY_LENGTH]);
                Ok(PublicKey {
                    key: PublicKeyData::DjbPublicKey(key),
                })
            }
        }
    }

    pub fn public_key_bytes(&self) -> Result<&[u8]> {
        match &self.key {
            PublicKeyData::DjbPublicKey(v) => Ok(v),
        }
    }

    pub fn from_djb_public_key_bytes(bytes: &[u8]) -> Result<Self> {
        match <[u8; curve25519::PUBLIC_KEY_LENGTH]>::try_from(bytes) {
            Err(_) => Err(SignalProtocolError::BadKeyLength(KeyType::Djb, bytes.len())),
            Ok(key) => Ok(PublicKey {
                key: PublicKeyData::DjbPublicKey(key),
            }),
        }
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let value_len = match &self.key {
            PublicKeyData::DjbPublicKey(v) => v.len(),
        };
        let mut result = Vec::with_capacity(1 + value_len);
        result.push(self.key_type().value());
        match &self.key {
            PublicKeyData::DjbPublicKey(v) => result.extend_from_slice(v),
        }
        result.into_boxed_slice()
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        self.verify_signature_for_multipart_message(&[message], signature)
    }

    pub fn verify_signature_for_multipart_message(
        &self,
        message: &[&[u8]],
        signature: &[u8],
    ) -> Result<bool> {
        match &self.key {
            PublicKeyData::DjbPublicKey(pub_key) => {
                if signature.len() != curve25519::SIGNATURE_LENGTH {
                    return Ok(false);
                }
                Ok(curve25519::PrivateKey::verify_signature(
                    pub_key,
                    message,
                    array_ref![signature, 0, curve25519::SIGNATURE_LENGTH],
                ))
            }
        }
    }

    fn key_data(&self) -> &[u8] {
        match &self.key {
            PublicKeyData::DjbPublicKey(ref k) => k.as_ref(),
        }
    }

    pub fn key_type(&self) -> KeyType {
        match &self.key {
            PublicKeyData::DjbPublicKey(_) => KeyType::Djb,
        }
    }
}

impl From<PublicKeyData> for PublicKey {
    fn from(key: PublicKeyData) -> PublicKey {
        Self { key }
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl subtle::ConstantTimeEq for PublicKey {
    /// A constant-time comparison as long as the two keys have a matching type.
    ///
    /// If the two keys have different types, the comparison short-circuits,
    /// much like comparing two slices of different lengths.
    fn ct_eq(&self, other: &PublicKey) -> subtle::Choice {
        if self.key_type() != other.key_type() {
            return 0.ct_eq(&1);
        }
        self.key_data().ct_eq(other.key_data())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.key_type() != other.key_type() {
            return self.key_type().cmp(&other.key_type());
        }

        crate::utils::constant_time_cmp(self.key_data(), other.key_data())
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PublicKey {{ key_type={}, serialize={:?} }}",
            self.key_type(),
            self.serialize()
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PrivateKeyData {
    DjbPrivateKey([u8; curve25519::PRIVATE_KEY_LENGTH]),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PrivateKey {
    key: PrivateKeyData,
}

impl PrivateKey {
    pub fn deserialize(value: &[u8]) -> Result<Self> {
        if value.len() != curve25519::PRIVATE_KEY_LENGTH {
            Err(SignalProtocolError::BadKeyLength(KeyType::Djb, value.len()))
        } else {
            let mut key = [0u8; curve25519::PRIVATE_KEY_LENGTH];
            key.copy_from_slice(&value[..curve25519::PRIVATE_KEY_LENGTH]);
            // Clamping is not necessary but is kept for backward compatibility
            key = scalar::clamp_integer(key);
            Ok(Self {
                key: PrivateKeyData::DjbPrivateKey(key),
            })
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match &self.key {
            PrivateKeyData::DjbPrivateKey(v) => v.to_vec(),
        }
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        match &self.key {
            PrivateKeyData::DjbPrivateKey(private_key) => {
                let public_key =
                    curve25519::PrivateKey::from(*private_key).derive_public_key_bytes();
                Ok(PublicKey::new(PublicKeyData::DjbPublicKey(public_key)))
            }
        }
    }

    pub fn key_type(&self) -> KeyType {
        match &self.key {
            PrivateKeyData::DjbPrivateKey(_) => KeyType::Djb,
        }
    }

    pub fn compressed_edwards_public_key(&self) -> Result<PublicKey> {
        match self.key {
            PrivateKeyData::DjbPrivateKey(k) => {
                let private_key = curve25519::PrivateKey::from(k);
                let key_data = private_key.private_key_bytes();
                let a = Scalar::from_bytes_mod_order(key_data);
                let ed_public_key_point = &a * ED25519_BASEPOINT_TABLE;
                let ed_public_key = ed_public_key_point.compress();

                Ok(PublicKey::new(PublicKeyData::DjbPublicKey(ed_public_key.to_bytes())))
            }
        }
    }

    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>> {
        self.calculate_signature_for_multipart_message(&[message], csprng)
    }

    pub fn calculate_signature_for_multipart_message<R: CryptoRng + Rng>(
        &self,
        message: &[&[u8]],
        csprng: &mut R,
    ) -> Result<Box<[u8]>> {
        match self.key {
            PrivateKeyData::DjbPrivateKey(k) => {
                let private_key = curve25519::PrivateKey::from(k);
                Ok(Box::new(private_key.calculate_signature(csprng, message)))
            }
        }
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>> {
        match (self.key, their_key.key) {
            (PrivateKeyData::DjbPrivateKey(priv_key), PublicKeyData::DjbPublicKey(pub_key)) => {
                let private_key = curve25519::PrivateKey::from(priv_key);
                Ok(Box::new(private_key.calculate_agreement(&pub_key)))
            }
        }
    }
}

impl From<PrivateKeyData> for PrivateKey {
    fn from(key: PrivateKeyData) -> PrivateKey {
        Self { key }
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

#[derive(Copy, Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    pub fn generate<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        let private_key = curve25519::PrivateKey::new(csprng);

        let public_key = PublicKey::from(PublicKeyData::DjbPublicKey(
            private_key.derive_public_key_bytes(),
        ));
        let private_key = PrivateKey::from(PrivateKeyData::DjbPrivateKey(
            private_key.private_key_bytes(),
        ));

        Self {
            public_key,
            private_key,
        }
    }

    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    pub fn from_public_and_private(public_key: &[u8], private_key: &[u8]) -> Result<Self> {
        let public_key = PublicKey::try_from(public_key)?;
        let private_key = PrivateKey::try_from(private_key)?;
        Ok(Self {
            public_key,
            private_key,
        })
    }

    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>> {
        self.private_key.calculate_signature(message, csprng)
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>> {
        self.private_key.calculate_agreement(their_key)
    }
}

impl TryFrom<PrivateKey> for KeyPair {
    type Error = SignalProtocolError;

    fn try_from(value: PrivateKey) -> Result<Self> {
        let public_key = value.public_key()?;
        Ok(Self::new(public_key, value))
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_large_signatures() -> Result<()> {
        let mut csprng = OsRng;
        let key_pair = KeyPair::generate(&mut csprng);
        let mut message = [0u8; 1024 * 1024];
        let signature = key_pair
            .private_key
            .calculate_signature(&message, &mut csprng)?;

        assert!(key_pair.public_key.verify_signature(&message, &signature)?);
        message[0] ^= 0x01u8;
        assert!(!key_pair.public_key.verify_signature(&message, &signature)?);
        message[0] ^= 0x01u8;
        let public_key = key_pair.private_key.public_key()?;
        assert!(public_key.verify_signature(&message, &signature)?);

        assert!(public_key
            .verify_signature_for_multipart_message(&[&message[..7], &message[7..]], &signature)?);

        let signature = key_pair
            .private_key
            .calculate_signature_for_multipart_message(
                &[&message[..20], &message[20..]],
                &mut csprng,
            )?;
        assert!(public_key.verify_signature(&message, &signature)?);

        Ok(())
    }

    #[test]
    fn test_decode_size() -> Result<()> {
        let mut csprng = OsRng;
        let key_pair = KeyPair::generate(&mut csprng);
        let serialized_public = key_pair.public_key.serialize();

        assert_eq!(
            serialized_public,
            key_pair.private_key.public_key()?.serialize()
        );
        let empty: [u8; 0] = [];

        let just_right = PublicKey::try_from(&serialized_public[..]);

        assert!(just_right.is_ok());
        assert!(PublicKey::try_from(&serialized_public[1..]).is_err());
        assert!(PublicKey::try_from(&empty[..]).is_err());

        let mut bad_key_type = [0u8; 33];
        bad_key_type[..].copy_from_slice(&serialized_public[..]);
        bad_key_type[0] = 0x01u8;
        assert!(PublicKey::try_from(&bad_key_type[..]).is_err());

        let mut extra_space = [0u8; 34];
        extra_space[..33].copy_from_slice(&serialized_public[..]);
        let extra_space_decode = PublicKey::try_from(&extra_space[..]);
        assert!(extra_space_decode.is_ok());

        assert_eq!(&serialized_public[..], &just_right?.serialize()[..]);
        assert_eq!(&serialized_public[..], &extra_space_decode?.serialize()[..]);
        Ok(())
    }
}
