//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod curve25519;
mod utils;

use std::cmp::Ordering;
use std::fmt;

use curve25519_dalek::{MontgomeryPoint, scalar};
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

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

#[derive(Debug, displaydoc::Display)]
pub enum CurveError {
    /// no key type identifier
    NoKeyTypeIdentifier,
    /// bad key type <{0:#04x}>
    BadKeyType(u8),
    /// bad key length <{1}> for key with type <{0}>
    BadKeyLength(KeyType, usize),
}

impl std::error::Error for CurveError {}

impl TryFrom<u8> for KeyType {
    type Error = CurveError;

    fn try_from(x: u8) -> Result<Self, CurveError> {
        match x {
            0x05u8 => Ok(KeyType::Djb),
            t => Err(CurveError::BadKeyType(t)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PublicKeyData {
    DjbPublicKey([u8; curve25519::PUBLIC_KEY_LENGTH]),
}

#[derive(Clone, Copy, Eq, derive_more::From)]
pub struct PublicKey {
    key: PublicKeyData,
}

impl PublicKey {
    fn new(key: PublicKeyData) -> Self {
        Self { key }
    }

    pub fn deserialize(value: &[u8]) -> Result<Self, CurveError> {
        let (key_type, value) = value.split_first().ok_or(CurveError::NoKeyTypeIdentifier)?;
        let key_type = KeyType::try_from(*key_type)?;
        match key_type {
            KeyType::Djb => {
                let (key, tail): (&[u8; curve25519::PUBLIC_KEY_LENGTH], _) = value
                    .split_first_chunk()
                    .ok_or(CurveError::BadKeyLength(KeyType::Djb, value.len() + 1))?;
                // We currently allow trailing data after the public key.
                // TODO: once this is known to not be seen in practice, make this a hard error.
                if !tail.is_empty() {
                    log::warn!(
                        "ECPublicKey deserialized with {} trailing bytes",
                        tail.len()
                    );
                }
                Ok(PublicKey {
                    key: PublicKeyData::DjbPublicKey(*key),
                })
            }
        }
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        match &self.key {
            PublicKeyData::DjbPublicKey(v) => v,
        }
    }

    pub fn from_djb_public_key_bytes(bytes: &[u8]) -> Result<Self, CurveError> {
        match <[u8; curve25519::PUBLIC_KEY_LENGTH]>::try_from(bytes) {
            Err(_) => Err(CurveError::BadKeyLength(KeyType::Djb, bytes.len())),
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

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        self.verify_signature_for_multipart_message(&[message], signature)
    }

    pub fn verify_signature_for_multipart_message(
        &self,
        message: &[&[u8]],
        signature: &[u8],
    ) -> bool {
        match &self.key {
            PublicKeyData::DjbPublicKey(pub_key) => {
                let Ok(signature) = signature.try_into() else {
                    return false;
                };
                curve25519::PrivateKey::verify_signature(pub_key, message, signature)
            }
        }
    }

    fn key_data(&self) -> &[u8] {
        match &self.key {
            PublicKeyData::DjbPublicKey(k) => k.as_ref(),
        }
    }

    pub fn key_type(&self) -> KeyType {
        match &self.key {
            PublicKeyData::DjbPublicKey(_) => KeyType::Djb,
        }
    }

    fn is_torsion_free(&self) -> bool {
        match &self.key {
            PublicKeyData::DjbPublicKey(k) => {
                let mont_point = MontgomeryPoint(*k);
                mont_point
                    .to_edwards(0)
                    .is_some_and(|ed| ed.is_torsion_free())
            }
        }
    }

    fn scalar_is_in_range(&self) -> bool {
        match &self.key {
            PublicKeyData::DjbPublicKey(k) => {
                // it is not true that the scalar is greater than 2^255 - 19
                // specifically, it is not true that either the high bit is set
                // or that the high 247 bits are all 1 and the bottom byte is >(2^8 - 19)
                !(k[31] & 0b1000_0000_u8 != 0
                    || (k[0] >= 0u8.wrapping_sub(19) && k[1..31] == [0xFFu8; 30] && k[31] == 0x7F))
            }
        }
    }

    pub fn is_canonical(&self) -> bool {
        self.is_torsion_free() && self.scalar_is_in_range()
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = CurveError;

    fn try_from(value: &[u8]) -> Result<Self, CurveError> {
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

        utils::constant_time_cmp(self.key_data(), other.key_data())
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

#[derive(Clone, Copy, Eq, PartialEq, derive_more::From)]
pub struct PrivateKey {
    key: PrivateKeyData,
}

impl PrivateKey {
    pub fn deserialize(value: &[u8]) -> Result<Self, CurveError> {
        let mut key: [u8; curve25519::PRIVATE_KEY_LENGTH] = value
            .try_into()
            .map_err(|_| CurveError::BadKeyLength(KeyType::Djb, value.len()))?;
        // Clamping is not necessary but is kept for backward compatibility
        key = scalar::clamp_integer(key);
        Ok(Self {
            key: PrivateKeyData::DjbPrivateKey(key),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        match &self.key {
            PrivateKeyData::DjbPrivateKey(v) => v.to_vec(),
        }
    }

    pub fn public_key(&self) -> Result<PublicKey, CurveError> {
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
    ) -> Result<Box<[u8]>, CurveError> {
        self.calculate_signature_for_multipart_message(&[message], csprng)
    }

    pub fn calculate_signature_for_multipart_message<R: CryptoRng + Rng>(
        &self,
        message: &[&[u8]],
        csprng: &mut R,
    ) -> Result<Box<[u8]>, CurveError> {
        match self.key {
            PrivateKeyData::DjbPrivateKey(k) => {
                let private_key = curve25519::PrivateKey::from(k);
                Ok(Box::new(private_key.calculate_signature(csprng, message)))
            }
        }
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>, CurveError> {
        match (self.key, their_key.key) {
            (PrivateKeyData::DjbPrivateKey(priv_key), PublicKeyData::DjbPublicKey(pub_key)) => {
                let private_key = curve25519::PrivateKey::from(priv_key);
                Ok(Box::new(private_key.calculate_agreement(&pub_key)))
            }
        }
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = CurveError;

    fn try_from(value: &[u8]) -> Result<Self, CurveError> {
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

    pub fn from_public_and_private(
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Self, CurveError> {
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
    ) -> Result<Box<[u8]>, CurveError> {
        self.private_key.calculate_signature(message, csprng)
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>, CurveError> {
        self.private_key.calculate_agreement(their_key)
    }
}

impl TryFrom<PrivateKey> for KeyPair {
    type Error = CurveError;

    fn try_from(value: PrivateKey) -> Result<Self, CurveError> {
        let public_key = value.public_key()?;
        Ok(Self::new(public_key, value))
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use const_str::hex;
    use curve25519_dalek::constants::EIGHT_TORSION;
    use rand::TryRngCore as _;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_large_signatures() -> Result<(), CurveError> {
        let mut csprng = OsRng.unwrap_err();
        let key_pair = KeyPair::generate(&mut csprng);
        let mut message = [0u8; 1024 * 1024];
        let signature = key_pair
            .private_key
            .calculate_signature(&message, &mut csprng)?;

        assert!(key_pair.public_key.verify_signature(&message, &signature));
        message[0] ^= 0x01u8;
        assert!(!key_pair.public_key.verify_signature(&message, &signature));
        message[0] ^= 0x01u8;
        let public_key = key_pair.private_key.public_key()?;
        assert!(public_key.verify_signature(&message, &signature));

        assert!(
            public_key.verify_signature_for_multipart_message(
                &[&message[..7], &message[7..]],
                &signature
            )
        );

        let signature = key_pair
            .private_key
            .calculate_signature_for_multipart_message(
                &[&message[..20], &message[20..]],
                &mut csprng,
            )?;
        assert!(public_key.verify_signature(&message, &signature));

        Ok(())
    }

    #[test]
    fn test_decode_size() -> Result<(), CurveError> {
        let mut csprng = OsRng.unwrap_err();
        let key_pair = KeyPair::generate(&mut csprng);
        let serialized_public = key_pair.public_key.serialize();

        assert_eq!(
            serialized_public,
            key_pair.private_key.public_key()?.serialize()
        );
        let empty: [u8; 0] = [];

        let just_right = PublicKey::try_from(&serialized_public[..])?;

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

        assert_eq!(&serialized_public[..], &just_right.serialize()[..]);
        assert_eq!(&serialized_public[..], &extra_space_decode?.serialize()[..]);
        Ok(())
    }

    #[test]
    fn curve_error_impls_std_error() {
        let error = CurveError::BadKeyType(u8::MAX);
        let error = Box::new(error) as Box<dyn std::error::Error>;
        assert_matches!(error.downcast_ref(), Some(CurveError::BadKeyType(_)));
    }

    #[test]
    fn honest_keys_are_torsion_free() {
        let mut csprng = OsRng.unwrap_err();
        let key_pair = KeyPair::generate(&mut csprng);
        assert!(key_pair.public_key.is_torsion_free());
    }

    #[test]
    fn tweaked_keys_are_not_torsion_free() {
        let mut csprng = OsRng.unwrap_err();
        let key_pair = KeyPair::generate(&mut csprng);
        let pk_bytes: [u8; 32] = key_pair.public_key.public_key_bytes().try_into().unwrap();
        let mont_pt = MontgomeryPoint(pk_bytes);
        let ed_pt = mont_pt.to_edwards(0).unwrap();
        for t in EIGHT_TORSION.iter().skip(1) {
            let tweaked = ed_pt + *t; // add a torsion point
            let tweaked_mont = tweaked.to_montgomery();
            let tweaked_pk_bytes: [u8; 32] = tweaked_mont.to_bytes();
            let tweaked_pk = PublicKey::from_djb_public_key_bytes(&tweaked_pk_bytes).unwrap();
            assert!(!tweaked_pk.is_torsion_free());
        }
    }

    #[test]
    fn keys_with_the_high_bit_set_are_out_of_range() {
        assert!(
            PublicKey::from_djb_public_key_bytes(&[0; 32])
                .expect("structurally valid")
                .scalar_is_in_range(),
            "0 should be in range"
        );
        assert!(
            !PublicKey::from_djb_public_key_bytes(&hex!(
                "0000000000000000000000000000000000000000000000000000000000000080"
            ))
            .expect("structurally valid")
            .scalar_is_in_range(),
            "2^255 should be out of range"
        );
        assert!(
            !PublicKey::from_djb_public_key_bytes(&[0xFF; 32])
                .expect("structurally valid")
                .scalar_is_in_range(),
            "2^256 - 1 should be out of range"
        );
        {
            let mut csprng = OsRng.unwrap_err();
            let key_pair = KeyPair::generate(&mut csprng);
            assert!(key_pair.public_key.scalar_is_in_range());
            let mut pk_bytes: [u8; 32] = key_pair.public_key.public_key_bytes().try_into().unwrap();
            assert!(pk_bytes[31] & 0x80 == 0);
            pk_bytes[31] |= 0x80;
            assert!(
                !PublicKey::from_djb_public_key_bytes(&pk_bytes)
                    .expect("structurally valid")
                    .scalar_is_in_range(),
                ">2^255 should be out of range"
            );
        }
    }

    #[test]
    fn keys_above_the_prime_modulus_are_out_of_range() {
        // Curve25519 scalars use a little-endian representation.
        let two_to_the_255_minus_one =
            hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

        for i in 1..=19 {
            let mut pk_bytes = two_to_the_255_minus_one;
            pk_bytes[0] -= i;
            pk_bytes[0] += 1; // because our original literal was 2^255 - 1
            assert!(
                !PublicKey::from_djb_public_key_bytes(&pk_bytes)
                    .expect("structurally valid")
                    .scalar_is_in_range(),
                "2^255 - {i} should be out of range",
            );

            let mut canonical_representative = [0; 32];
            canonical_representative[0] = 19 - i;

            assert_eq!(
                MontgomeryPoint(pk_bytes),
                MontgomeryPoint(canonical_representative)
            );
        }

        let mut pk_bytes = two_to_the_255_minus_one;
        pk_bytes[0] -= 19; // resulting in the value 2^255 - 20
        assert!(
            PublicKey::from_djb_public_key_bytes(&pk_bytes)
                .expect("structurally valid")
                .scalar_is_in_range()
        );
    }
}
