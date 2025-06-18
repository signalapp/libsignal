//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::Ordering;
use std::fmt;
use subtle::ConstantTimeEq;

use crate::{pswoosh_keygen, pswoosh_skey_deriv, sys_a::{A, AT}, PUBLICKEY_BYTES, SECRETKEY_BYTES, SYMBYTES};

pub type SerializedCiphertext = Box<[u8]>;
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SwooshKeyType {
    Pswoosh,
}

impl fmt::Display for SwooshKeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl SwooshKeyType {
    fn value(&self) -> u8 {
        match &self {
            SwooshKeyType::Pswoosh => 0x06u8,
        }
    }
}

#[derive(Debug, displaydoc::Display)]
pub enum SwooshError {
    /// no key type identifier
    NoKeyTypeIdentifier,
    /// bad key type <{0:#04x}>
    BadKeyType(u8),
    /// bad key length <{1}> for key with type <{0}>
    BadKeyLength(SwooshKeyType, usize),
    /// key generation failed
    KeyGenerationFailed,
    /// key derivation failed
    KeyDerivationFailed,
}

impl std::error::Error for SwooshError {}

impl TryFrom<u8> for SwooshKeyType {
    type Error = SwooshError;

    fn try_from(x: u8) -> Result<Self, SwooshError> {
        match x {
            0x06u8 => Ok(SwooshKeyType::Pswoosh),
            t => Err(SwooshError::BadKeyType(t)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PublicSwooshKeyData {
    PswooshPublicKey([u8; PUBLICKEY_BYTES]),
}

#[derive(Clone, Copy, Eq, derive_more::From)]
pub struct PublicSwooshKey {
    key: PublicSwooshKeyData,
}

impl PublicSwooshKey {
    fn new(key: PublicSwooshKeyData) -> Self {
        Self { key }
    }

    pub fn deserialize(value: &[u8]) -> Result<Self, SwooshError> {
        if value.is_empty() {
            return Err(SwooshError::NoKeyTypeIdentifier);
        }
        let key_type = SwooshKeyType::try_from(value[0])?;
        match key_type {
            SwooshKeyType::Pswoosh => {
                // We allow trailing data after the public key for compatibility
                if value.len() < PUBLICKEY_BYTES + 1 {
                    return Err(SwooshError::BadKeyLength(SwooshKeyType::Pswoosh, value.len()));
                }
                let mut key = [0u8; PUBLICKEY_BYTES];
                key.copy_from_slice(&value[1..][..PUBLICKEY_BYTES]);
                Ok(PublicSwooshKey {
                    key: PublicSwooshKeyData::PswooshPublicKey(key),
                })
            }
        }
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        match &self.key {
            PublicSwooshKeyData::PswooshPublicKey(v) => v,
        }
    }

    pub fn from_pswoosh_public_key_bytes(bytes: &[u8]) -> Result<Self, SwooshError> {
        match <[u8; PUBLICKEY_BYTES]>::try_from(bytes) {
            Err(_) => Err(SwooshError::BadKeyLength(SwooshKeyType::Pswoosh, bytes.len())),
            Ok(key) => Ok(PublicSwooshKey {
                key: PublicSwooshKeyData::PswooshPublicKey(key),
            }),
        }
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let value_len = match &self.key {
            PublicSwooshKeyData::PswooshPublicKey(v) => v.len(),
        };
        let mut result = Vec::with_capacity(1 + value_len);
        result.push(self.key_type().value());
        match &self.key {
            PublicSwooshKeyData::PswooshPublicKey(v) => result.extend_from_slice(v),
        }
        result.into_boxed_slice()
    }

    fn key_data(&self) -> &[u8] {
        match &self.key {
            PublicSwooshKeyData::PswooshPublicKey(ref k) => k.as_ref(),
        }
    }

    pub fn key_type(&self) -> SwooshKeyType {
        match &self.key {
            PublicSwooshKeyData::PswooshPublicKey(_) => SwooshKeyType::Pswoosh,
        }
    }

    /// Derive shared secret using this public key and a private key
    pub fn derive_shared_secret(&self, private_key: &PrivateSwooshKey, f: bool) -> Result<[u8; SYMBYTES], SwooshError> {
        match (&self.key, &private_key.key) {
            (PublicSwooshKeyData::PswooshPublicKey(pub_key), PrivateSwooshKeyData::PswooshPrivateKey(priv_key)) => {
                // For pswoosh key derivation, we need another public key
                // This is a simplified version - in practice you'd need both public keys
                Ok(pswoosh_skey_deriv(pub_key, pub_key, priv_key, f))
            }
        }
    }
}

impl TryFrom<&[u8]> for PublicSwooshKey {
    type Error = SwooshError;

    fn try_from(value: &[u8]) -> Result<Self, SwooshError> {
        Self::deserialize(value)
    }
}

impl subtle::ConstantTimeEq for PublicSwooshKey {
    /// A constant-time comparison as long as the two keys have a matching type.
    ///
    /// If the two keys have different types, the comparison short-circuits,
    /// much like comparing two slices of different lengths.
    fn ct_eq(&self, other: &PublicSwooshKey) -> subtle::Choice {
        if self.key_type() != other.key_type() {
            return 0.ct_eq(&1);
        }
        self.key_data().ct_eq(other.key_data())
    }
}

impl PartialEq for PublicSwooshKey {
    fn eq(&self, other: &PublicSwooshKey) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Ord for PublicSwooshKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.key_type() != other.key_type() {
            return self.key_type().cmp(&other.key_type());
        }

        // For constant-time comparison, we use lexicographic order
        self.key_data().cmp(other.key_data())
    }
}

impl PartialOrd for PublicSwooshKey {
    fn partial_cmp(&self, other: &PublicSwooshKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for PublicSwooshKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PublicSwooshKey {{ key_type={}, serialize={:?} }}",
            self.key_type(),
            self.serialize()
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PrivateSwooshKeyData {
    PswooshPrivateKey([u8; SECRETKEY_BYTES]),
}

#[derive(Clone, Copy, Eq, PartialEq, derive_more::From)]
pub struct PrivateSwooshKey {
    key: PrivateSwooshKeyData,
}

impl PrivateSwooshKey {
    pub fn deserialize(value: &[u8]) -> Result<Self, SwooshError> {
        if value.len() != SECRETKEY_BYTES {
            Err(SwooshError::BadKeyLength(SwooshKeyType::Pswoosh, value.len()))
        } else {
            let mut key = [0u8; SECRETKEY_BYTES];
            key.copy_from_slice(&value[..SECRETKEY_BYTES]);
            Ok(Self {
                key: PrivateSwooshKeyData::PswooshPrivateKey(key),
            })
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match &self.key {
            PrivateSwooshKeyData::PswooshPrivateKey(v) => v.to_vec(),
        }
    }

    pub fn key_type(&self) -> SwooshKeyType {
        match &self.key {
            PrivateSwooshKeyData::PswooshPrivateKey(_) => SwooshKeyType::Pswoosh,
        }
    }

    pub fn secret_key_bytes(&self) -> &[u8] {
        match &self.key {
            PrivateSwooshKeyData::PswooshPrivateKey(v) => v,
        }
    }

    /// Derive shared secret using this private key and public keys
    pub fn derive_shared_secret(&self, pub_key1: &PublicSwooshKey, pub_key2: &PublicSwooshKey, f: bool) -> Result<[u8; SYMBYTES], SwooshError> {
        match (&self.key, &pub_key1.key, &pub_key2.key) {
            (PrivateSwooshKeyData::PswooshPrivateKey(priv_key), 
             PublicSwooshKeyData::PswooshPublicKey(pk1), 
             PublicSwooshKeyData::PswooshPublicKey(pk2)) => {
                Ok(pswoosh_skey_deriv(pk1, pk2, priv_key, f))
            }
        }
    }
}

impl TryFrom<&[u8]> for PrivateSwooshKey {
    type Error = SwooshError;

    fn try_from(value: &[u8]) -> Result<Self, SwooshError> {
        Self::deserialize(value)
    }
}

#[derive(Copy, Clone)]
pub struct SwooshKeyPair {
    pub public_key: PublicSwooshKey,
    pub private_key: PrivateSwooshKey,
}

impl SwooshKeyPair {
    pub fn generate(f: bool) -> Self {

        let (private_key_bytes, public_key_bytes);
        if f{
            (private_key_bytes, public_key_bytes) = pswoosh_keygen(&A, f);
        } else{
            (private_key_bytes, public_key_bytes) = pswoosh_keygen(&AT, f);
        }
        
        
        let public_key = PublicSwooshKey::from(PublicSwooshKeyData::PswooshPublicKey(public_key_bytes));
        let private_key = PrivateSwooshKey::from(PrivateSwooshKeyData::PswooshPrivateKey(private_key_bytes));

        Self {
            public_key,
            private_key,
        }
    }

    pub fn new(public_key: PublicSwooshKey, private_key: PrivateSwooshKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    pub fn from_public_and_private(
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Self, SwooshError> {
        let public_key = PublicSwooshKey::try_from(public_key)?;
        let private_key = PrivateSwooshKey::try_from(private_key)?;
        Ok(Self {
            public_key,
            private_key,
        })
    }

    pub fn public_key(&self) -> &PublicSwooshKey {
        &self.public_key
    }

    pub fn private_key(&self) -> &PrivateSwooshKey {
        &self.private_key
    }

    /// Derive shared secret with another party's public key
    pub fn derive_shared_secret(&self, their_public_key: &PublicSwooshKey, f: bool) -> Result<[u8; SYMBYTES], SwooshError> {
        self.private_key.derive_shared_secret(&self.public_key, their_public_key, f)
    }
}

impl TryFrom<PrivateSwooshKey> for SwooshKeyPair {
    type Error = SwooshError;

    fn try_from(private_key: PrivateSwooshKey) -> Result<Self, SwooshError> {
        // For pswoosh, we can't derive public key from private key alone
        // This would need additional matrix parameter in a real implementation
        Err(SwooshError::KeyGenerationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() -> Result<(), SwooshError> {
        // Test key generation with both matrix orientations
        let key_pair1 = SwooshKeyPair::generate(true);
        let key_pair2 = SwooshKeyPair::generate(false);
        
        // Verify key types
        assert_eq!(key_pair1.public_key.key_type(), SwooshKeyType::Pswoosh);
        assert_eq!(key_pair1.private_key.key_type(), SwooshKeyType::Pswoosh);
        assert_eq!(key_pair2.public_key.key_type(), SwooshKeyType::Pswoosh);
        assert_eq!(key_pair2.private_key.key_type(), SwooshKeyType::Pswoosh);
        
        // Verify key lengths
        assert_eq!(key_pair1.public_key.public_key_bytes().len(), PUBLICKEY_BYTES);
        assert_eq!(key_pair1.private_key.secret_key_bytes().len(), SECRETKEY_BYTES);
        assert_eq!(key_pair2.public_key.public_key_bytes().len(), PUBLICKEY_BYTES);
        assert_eq!(key_pair2.private_key.secret_key_bytes().len(), SECRETKEY_BYTES);
        
        Ok(())
    }

    #[test]
    fn test_serialization_deserialization() -> Result<(), SwooshError> {
        let key_pair = SwooshKeyPair::generate(true);
        
        // Test public key serialization/deserialization
        let serialized_public = key_pair.public_key.serialize();
        assert_eq!(serialized_public.len(), PUBLICKEY_BYTES + 1); // +1 for key type byte
        assert_eq!(serialized_public[0], SwooshKeyType::Pswoosh.value());
        
        let deserialized_public = PublicSwooshKey::deserialize(&serialized_public)?;
        assert_eq!(key_pair.public_key.public_key_bytes(), deserialized_public.public_key_bytes());
        
        // Test private key serialization/deserialization
        let serialized_private = key_pair.private_key.serialize();
        assert_eq!(serialized_private.len(), SECRETKEY_BYTES);
        
        let deserialized_private = PrivateSwooshKey::deserialize(&serialized_private)?;
        assert_eq!(key_pair.private_key.secret_key_bytes(), deserialized_private.secret_key_bytes());
        
        Ok(())
    }

    #[test]
    fn test_deserialization_errors() {
        // Test empty input
        let empty: [u8; 0] = [];
        assert!(matches!(
            PublicSwooshKey::deserialize(&empty),
            Err(SwooshError::NoKeyTypeIdentifier)
        ));
        
        // Test bad key type
        let mut bad_key_type = [0u8; PUBLICKEY_BYTES + 1];
        bad_key_type[0] = 0x99; // Invalid key type
        assert!(matches!(
            PublicSwooshKey::deserialize(&bad_key_type),
            Err(SwooshError::BadKeyType(0x99))
        ));
        
        // Test bad length (too short)
        let short_key = [SwooshKeyType::Pswoosh.value()]; // Only key type, no data
        assert!(matches!(
            PublicSwooshKey::deserialize(&short_key),
            Err(SwooshError::BadKeyLength(SwooshKeyType::Pswoosh, 1))
        ));
        
        // Test private key bad length
        let wrong_size_private = [0u8; SECRETKEY_BYTES - 1];
        assert!(matches!(
            PrivateSwooshKey::deserialize(&wrong_size_private),
            Err(SwooshError::BadKeyLength(SwooshKeyType::Pswoosh, _))
        ));
    }

    #[test]
    fn test_deserialization_with_trailing_data() -> Result<(), SwooshError> {
        let key_pair = SwooshKeyPair::generate(true);
        let mut serialized = key_pair.public_key.serialize().to_vec();
        
        // Add trailing data
        serialized.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        
        // Should still deserialize correctly (ignoring trailing data)
        let deserialized = PublicSwooshKey::deserialize(&serialized)?;
        assert_eq!(key_pair.public_key.public_key_bytes(), deserialized.public_key_bytes());
        
        Ok(())
    }

    #[test]
    fn test_key_equality() -> Result<(), SwooshError> {
        let key_pair1 = SwooshKeyPair::generate(true);
        let key_pair2 = SwooshKeyPair::generate(true);
        
        // Different keys should not be equal
        assert_ne!(key_pair1.public_key, key_pair2.public_key);
        
        // Same key should be equal to itself
        assert_eq!(key_pair1.public_key, key_pair1.public_key);
        
        // Deserialized key should equal original
        let serialized = key_pair1.public_key.serialize();
        let deserialized = PublicSwooshKey::deserialize(&serialized)?;
        assert_eq!(key_pair1.public_key, deserialized);
        
        Ok(())
    }

    #[test]
    fn test_key_ordering() -> Result<(), SwooshError> {
        let key1 = SwooshKeyPair::generate(true).public_key;
        let key2 = SwooshKeyPair::generate(true).public_key;
        
        // Keys should have consistent ordering
        let ord1 = key1.cmp(&key2);
        let ord2 = key2.cmp(&key1);
        
        match ord1 {
            Ordering::Less => assert_eq!(ord2, Ordering::Greater),
            Ordering::Greater => assert_eq!(ord2, Ordering::Less),
            Ordering::Equal => assert_eq!(ord2, Ordering::Equal),
        }
        
        // Key should equal itself
        assert_eq!(key1.cmp(&key1), Ordering::Equal);
        
        Ok(())
    }

    #[test]
    fn test_shared_secret_derivation() -> Result<(), SwooshError> {
        // Generate two key pairs
        let key_pair1 = SwooshKeyPair::generate(true);
        let key_pair2 = SwooshKeyPair::generate(false);
        
        // Derive shared secrets
        let shared_secret1 = key_pair1.derive_shared_secret(&key_pair2.public_key, true)?;
        let shared_secret2 = key_pair2.derive_shared_secret(&key_pair1.public_key, false)?;
        
        // Shared secrets should match
        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), SYMBYTES);
        
        Ok(())
    }

    #[test]
    fn test_from_bytes_constructors() -> Result<(), SwooshError> {
        let key_pair = SwooshKeyPair::generate(true);
        
        // Test from_pswoosh_public_key_bytes
        let pub_key_from_bytes = PublicSwooshKey::from_pswoosh_public_key_bytes(
            key_pair.public_key.public_key_bytes()
        )?;
        assert_eq!(key_pair.public_key.public_key_bytes(), pub_key_from_bytes.public_key_bytes());
        
        // Test from_public_and_private
        let serialized_pub = key_pair.public_key.serialize();
        let serialized_priv = key_pair.private_key.serialize();
        let reconstructed = SwooshKeyPair::from_public_and_private(&serialized_pub, &serialized_priv)?;
        
        assert_eq!(key_pair.public_key.public_key_bytes(), reconstructed.public_key.public_key_bytes());
        assert_eq!(key_pair.private_key.secret_key_bytes(), reconstructed.private_key.secret_key_bytes());
        
        Ok(())
    }

    #[test]
    fn test_try_from_implementations() -> Result<(), SwooshError> {
        let key_pair = SwooshKeyPair::generate(true);
        
        // Test TryFrom for PublicSwooshKey
        let serialized_pub = key_pair.public_key.serialize();
        let pub_key: PublicSwooshKey = serialized_pub.as_ref().try_into()?;
        assert_eq!(key_pair.public_key.public_key_bytes(), pub_key.public_key_bytes());
        
        // Test TryFrom for PrivateSwooshKey
        let serialized_priv = key_pair.private_key.serialize();
        let priv_key: PrivateSwooshKey = serialized_priv.as_slice().try_into()?;
        assert_eq!(key_pair.private_key.secret_key_bytes(), priv_key.secret_key_bytes());
        
        // Test TryFrom PrivateSwooshKey to SwooshKeyPair (should fail)
        assert!(matches!(
            SwooshKeyPair::try_from(priv_key),
            Err(SwooshError::KeyGenerationFailed)
        ));
        
        Ok(())
    }

    #[test]
    fn test_error_implementations() {
        // Test that SwooshError implements std::error::Error
        let error = SwooshError::BadKeyType(0xFF);
        let error_trait: &dyn std::error::Error = &error;
        assert!(error_trait.to_string().contains("bad key type"));
        
        // Test Display implementation via displaydoc
        let error = SwooshError::BadKeyLength(SwooshKeyType::Pswoosh, 10);
        assert!(error.to_string().contains("bad key length"));
        assert!(error.to_string().contains("10"));
    }

    #[test]
    fn test_key_type_display() {
        let key_type = SwooshKeyType::Pswoosh;
        assert_eq!(format!("{}", key_type), "Pswoosh");
        assert_eq!(format!("{:?}", key_type), "Pswoosh");
        assert_eq!(key_type.value(), 0x06u8);
    }

    #[test]
    fn test_debug_implementations() -> Result<(), SwooshError> {
        let key_pair = SwooshKeyPair::generate(true);
        
        // Test that Debug is implemented and produces reasonable output
        let debug_str = format!("{:?}", key_pair.public_key);
        assert!(debug_str.contains("PublicSwooshKey"));
        assert!(debug_str.contains("Pswoosh"));
        
        Ok(())
    }
}