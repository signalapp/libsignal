//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub(crate) mod curve25519;

use crate::{Result, SignalProtocolError};

use std::convert::TryFrom;
use std::fmt;

use arrayref::array_ref;
use displaydoc::Display;
use num_enum;
use rand::{CryptoRng, Rng};
use subtle::{self, Convertible, IteratedEq, IteratedGreater, IteratedOperation};
use subtle_ng_derive::{ConstEq, ConstOrd, ConstantTimeEq, ConstantTimeGreater};

#[derive(
    Debug,
    Display,
    Copy,
    Clone,
    ConstEq,
    ConstOrd,
    num_enum::TryFromPrimitive,
    num_enum::IntoPrimitive,
)]
#[repr(u8)]
pub enum KeyType {
    /// <curve25519 key type>
    Djb = 0x05u8,
}

impl Convertible for KeyType {
    type To = u8;
    fn for_constant_operation(&self) -> u8 {
        (*self).into()
    }
}

#[derive(Debug, Clone, Copy, ConstEq, ConstOrd)]
enum PublicKeyData {
    DjbPublicKey([u8; curve25519::PUBLIC_KEY_LENGTH]),
}

impl PublicKeyData {
    pub(crate) fn key_type(&self) -> KeyType {
        match self {
            Self::DjbPublicKey(_) => KeyType::Djb,
        }
    }
    pub(crate) fn key_data(&self) -> &[u8] {
        match self {
            Self::DjbPublicKey(ref k) => k.as_ref(),
        }
    }
}

impl subtle::ConstantTimeEq for PublicKeyData {
    /// A constant-time comparison as long as the two keys have a matching type.
    ///
    /// If the two keys have different types, the comparison short-circuits,
    /// much like comparing two slices of different lengths.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        let mut x = IteratedEq::initiate();
        x.apply_eq(&self.key_type(), &other.key_type());
        x.apply_eq(self.key_data(), other.key_data());
        x.extract_result()
    }
}

impl subtle::ConstantTimeGreater for PublicKeyData {
    fn ct_gt(&self, other: &Self) -> subtle::Choice {
        let mut x = IteratedGreater::initiate();
        x.apply_gt(&self.key_type(), &other.key_type());
        x.apply_gt(self.key_data(), other.key_data());
        x.extract_result()
    }
}

impl subtle::ConstantTimeLess for PublicKeyData {}

#[derive(Clone, Copy, ConstEq, ConstOrd, ConstantTimeEq, ConstantTimeGreater)]
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
        let key_type =
            KeyType::try_from(value[0]).map_err(|e| SignalProtocolError::BadKeyType(e.number))?;
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
        result.push(self.key.key_type().into());
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

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PublicKey {{ key_type={}, serialize={:?} }}",
            self.key.key_type(),
            self.serialize()
        )
    }
}

#[derive(Debug, Clone, Copy)]
enum PrivateKeyData {
    DjbPrivateKey([u8; curve25519::PRIVATE_KEY_LENGTH]),
}

#[derive(Clone, Copy)]
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
            // Clamp:
            key[0] &= 0xF8;
            key[31] &= 0x7F;
            key[31] |= 0x40;
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
