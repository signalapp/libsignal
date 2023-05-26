//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Keys and protocol functions for standard key encapsulation mechanisms (KEMs).
//!
//! A KEM allows the holder of a `PublicKey` to create a shared secret with the
//! holder of the corresponding `SecretKey`. This is done by calling the function
//! `encapsulate` on the `PublicKey` to produce a `SharedSecret` and `Ciphertext`.
//! The `Ciphertext` is then sent to the recipient who can now call
//! `SecretKey::decapsulate(ct: Ciphertext)` to construct the same `SharedSecret`.
//!
//! # Supported KEMs
//! The NIST standardized Kyber1024 and Kyber768 KEMs are currently supported.
//!
//! # Serialization
//! `PublicKey`s and `SecretKey`s have serialization functions that encode the
//! KEM protocol. Calls to `PublicKey::deserialize()` and `SecretKey::deserialize()`
//! will use this to ensure the key is used for the correct KEM protocol.
//!
//! # Example
//! Basic usage:
//! ```
//! # use libsignal_protocol::kem::*;
//! // Generate a Kyber1024 key pair
//! let kp = KeyPair::generate(KeyType::Kyber1024);
//!
//! // The sender computes the shared secret and the ciphertext to send
//! let (ss_for_sender, ct) = kp.public_key.encapsulate();
//!
//! // Once the recipient receives the ciphertext, they use it with the
//! // secret key to construct the (same) shared secret.
//! let ss_for_recipient = kp.secret_key.decapsulate(&ct).expect("decapsulation succeeds");
//! assert_eq!(ss_for_recipient, ss_for_sender);
//! ```
//!
//! Serialization:
//! ```
//! # use libsignal_protocol::kem::*;
//! // Generate a Kyber768 key pair
//! let kp = KeyPair::generate(KeyType::Kyber768);
//!
//! let pk_for_wire = kp.public_key.serialize();
//! // serialized form has an extra byte to encode the protocol
//! assert_eq!(pk_for_wire.len(), 1184 + 1);
//!
//! let kp_reconstituted = PublicKey::deserialize(pk_for_wire.as_ref()).expect("deserialized correctly");
//! assert_eq!(kp_reconstituted.key_type(), KeyType::Kyber768);
//!
//! ```
//!
mod kyber1024;
mod kyber768;

use crate::{Result, SignalProtocolError};

use displaydoc::Display;
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::ops::Deref;
use subtle::ConstantTimeEq;

type SharedSecret = Box<[u8]>;

// The difference between the two is that the raw one does not contain the KeyType byte prefix.
pub(crate) type RawCiphertext = Box<[u8]>;
pub type SerializedCiphertext = Box<[u8]>;

/// Each KEM supported by libsignal-protocol implements this trait.
///
/// Similar to the traits in RustCrypto's [kem](https://docs.rs/kem/) crate.
///
/// # Example
/// ```ignore
/// struct MyNiftyKEM;
/// # #[cfg(ignore_even_when_running_all_tests)]
/// impl Parameters for MyNiftyKEM {
///     // ...
/// }
/// ```
trait Parameters {
    const PUBLIC_KEY_LENGTH: usize;
    const SECRET_KEY_LENGTH: usize;
    const CIPHERTEXT_LENGTH: usize;
    const SHARED_SECRET_LENGTH: usize;
    fn generate() -> (KeyMaterial<Public>, KeyMaterial<Secret>);
    fn encapsulate(pub_key: &KeyMaterial<Public>) -> (SharedSecret, RawCiphertext);
    fn decapsulate(secret_key: &KeyMaterial<Secret>, ciphertext: &[u8]) -> Result<SharedSecret>;
}

/// Acts as a bridge between the static [Parameters] trait and the dynamic [KeyType] enum.
trait DynParameters {
    fn public_key_length(&self) -> usize;
    fn secret_key_length(&self) -> usize;
    fn ciphertext_length(&self) -> usize;
    fn shared_secret_length(&self) -> usize;
    fn generate(&self) -> (KeyMaterial<Public>, KeyMaterial<Secret>);
    fn encapsulate(&self, pub_key: &KeyMaterial<Public>) -> (SharedSecret, RawCiphertext);
    fn decapsulate(
        &self,
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<SharedSecret>;
}

impl<T: Parameters> DynParameters for T {
    fn public_key_length(&self) -> usize {
        Self::PUBLIC_KEY_LENGTH
    }

    fn secret_key_length(&self) -> usize {
        Self::SECRET_KEY_LENGTH
    }

    fn ciphertext_length(&self) -> usize {
        Self::CIPHERTEXT_LENGTH
    }

    fn shared_secret_length(&self) -> usize {
        Self::SECRET_KEY_LENGTH
    }

    fn generate(&self) -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
        Self::generate()
    }

    fn encapsulate(&self, pub_key: &KeyMaterial<Public>) -> (SharedSecret, RawCiphertext) {
        Self::encapsulate(pub_key)
    }

    fn decapsulate(
        &self,
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<SharedSecret> {
        Self::decapsulate(secret_key, ciphertext)
    }
}

/// Designates a supported KEM protocol
#[derive(Display, Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyType {
    /// Kyber768 key
    Kyber768,
    /// Kyber1024 key
    Kyber1024,
}

impl KeyType {
    fn value(&self) -> u8 {
        match self {
            KeyType::Kyber768 => 0x07,
            KeyType::Kyber1024 => 0x08,
        }
    }

    /// Allows KeyType to act like `&dyn Parameters` while still being represented by a single byte.
    ///
    /// Declared `const` to encourage inlining.
    const fn parameters(&self) -> &'static dyn DynParameters {
        match self {
            KeyType::Kyber768 => &kyber768::Parameters,
            KeyType::Kyber1024 => &kyber1024::Parameters,
        }
    }
}

impl TryFrom<u8> for KeyType {
    type Error = SignalProtocolError;

    fn try_from(x: u8) -> Result<Self> {
        match x {
            0x07 => Ok(KeyType::Kyber768),
            0x08 => Ok(KeyType::Kyber1024),
            t => Err(SignalProtocolError::BadKEMKeyType(t)),
        }
    }
}

pub trait KeyKind {
    fn key_length(key_type: KeyType) -> usize;
}

#[derive(Clone, Debug)]
pub struct Public;

impl KeyKind for Public {
    fn key_length(key_type: KeyType) -> usize {
        key_type.parameters().public_key_length()
    }
}

#[derive(Clone, Debug)]
pub struct Secret;

impl KeyKind for Secret {
    fn key_length(key_type: KeyType) -> usize {
        key_type.parameters().secret_key_length()
    }
}

#[derive(Clone)]
pub(crate) struct KeyMaterial<T: KeyKind> {
    data: Box<[u8]>,
    kind: PhantomData<T>,
}

impl<T: KeyKind> KeyMaterial<T> {
    fn new(data: Box<[u8]>) -> Self {
        KeyMaterial {
            data,
            kind: PhantomData,
        }
    }
}

impl<T: KeyKind> Deref for KeyMaterial<T> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data.deref()
    }
}

#[derive(Clone)]
pub struct Key<T: KeyKind> {
    key_type: KeyType,
    key_data: KeyMaterial<T>,
}

impl<T: KeyKind> Key<T> {
    /// Create a `Key<Kind>` instance from a byte string created with the
    /// function `Key<Kind>::serialize(&self)`.
    pub fn deserialize(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0])?;
        if value.len() != T::key_length(key_type) + 1 {
            return Err(SignalProtocolError::BadKEMKeyLength(key_type, value.len()));
        }
        Ok(Key {
            key_type,
            key_data: KeyMaterial::new(value[1..].into()),
        })
    }
    /// Create a binary representation of the key that includes a protocol identifier.
    pub fn serialize(&self) -> Box<[u8]> {
        let mut result = Vec::with_capacity(1 + self.key_data.len());
        result.push(self.key_type.value());
        result.extend_from_slice(&self.key_data);
        result.into_boxed_slice()
    }

    /// Return the `KeyType` that identifies the KEM protocol for this key.
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
}

impl Key<Public> {
    /// Create a `SharedSecret` and a `Ciphertext`. The `Ciphertext` can be safely sent to the
    /// holder of the corresponding `SecretKey` who can then use it to `decapsulate` the same
    /// `SharedSecret`.
    pub fn encapsulate(&self) -> (SharedSecret, SerializedCiphertext) {
        let (ss, ct) = self.key_type.parameters().encapsulate(&self.key_data);
        (
            ss,
            Ciphertext {
                key_type: self.key_type,
                data: &ct,
            }
            .serialize(),
        )
    }
}

impl Key<Secret> {
    /// Decapsulates a `SharedSecret` that was encapsulated into a `Ciphertext` by a holder of
    /// the corresponding `PublicKey`.
    pub fn decapsulate(&self, ct_bytes: &SerializedCiphertext) -> Result<Box<[u8]>> {
        // deserialization checks that the length is correct for the KeyType
        let ct = Ciphertext::deserialize(ct_bytes)?;
        if ct.key_type != self.key_type {
            return Err(SignalProtocolError::WrongKEMKeyType(
                ct.key_type.value(),
                self.key_type.value(),
            ));
        }
        self.key_type
            .parameters()
            .decapsulate(&self.key_data, ct.data)
    }
}

impl TryFrom<&[u8]> for Key<Public> {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl TryFrom<&[u8]> for Key<Secret> {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl subtle::ConstantTimeEq for Key<Public> {
    /// A constant-time comparison as long as the two keys have a matching type.
    ///
    /// If the two keys have different types, the comparison short-circuits,
    /// much like comparing two slices of different lengths.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        if self.key_type != other.key_type {
            return 0.ct_eq(&1);
        }
        self.key_data.ct_eq(&other.key_data)
    }
}

impl PartialEq for Key<Public> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Key<Public> {}

/// A KEM public key with the ability to encapsulate a shared secret.
pub type PublicKey = Key<Public>;

/// A KEM secret key with the ability to decapsulate a shared secret.
pub type SecretKey = Key<Secret>;

/// A public/secret key pair for a KEM protocol.
#[derive(Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl KeyPair {
    /// Creates a public-secret key pair for a specified KEM protocol. Uses system randomness
    /// [implemented by PQClean](https://github.com/PQClean/PQClean/blob/c1b19a865de329e87e9b3e9152362fcb709da8ab/common/randombytes.c#L335).
    pub fn generate(key_type: KeyType) -> Self {
        let (pk, sk) = key_type.parameters().generate();
        Self {
            secret_key: SecretKey {
                key_type,
                key_data: sk,
            },
            public_key: PublicKey {
                key_type,
                key_data: pk,
            },
        }
    }

    pub fn new(public_key: PublicKey, secret_key: SecretKey) -> Self {
        assert_eq!(public_key.key_type, secret_key.key_type);
        Self {
            public_key,
            secret_key,
        }
    }

    /// Deserialize public and secret keys that were serialized by `PublicKey::serialize()`
    /// and `SecretKey::serialize()` respectively.
    pub fn from_public_and_private(public_key: &[u8], secret_key: &[u8]) -> Result<Self> {
        let public_key = PublicKey::try_from(public_key)?;
        let secret_key = SecretKey::try_from(secret_key)?;
        if public_key.key_type != secret_key.key_type {
            Err(SignalProtocolError::WrongKEMKeyType(
                secret_key.key_type.value(),
                public_key.key_type.value(),
            ))
        } else {
            Ok(Self {
                public_key,
                secret_key,
            })
        }
    }
}

/// Utility type to handle serialization and deserialization of ciphertext data
struct Ciphertext<'a> {
    key_type: KeyType,
    data: &'a [u8],
}

impl<'a> Ciphertext<'a> {
    /// Create a `Ciphertext` instance from a byte string created with the
    /// function `Ciphertext::serialize(&self)`.
    pub fn deserialize(value: &'a [u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0])?;
        if value.len() != key_type.parameters().ciphertext_length() + 1 {
            return Err(SignalProtocolError::BadKEMCiphertextLength(
                key_type,
                value.len(),
            ));
        }
        Ok(Ciphertext {
            key_type,
            data: &value[1..],
        })
    }

    /// Create a binary representation of the key that includes a protocol identifier.
    pub fn serialize(&self) -> SerializedCiphertext {
        let mut result = Vec::with_capacity(1 + self.data.len());
        result.push(self.key_type.value());
        result.extend_from_slice(self.data);
        result.into_boxed_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Result;
    use pqcrypto_kyber::kyber1024::{decapsulate, encapsulate, keypair};

    #[test]
    fn test_serialize() -> Result<()> {
        let pk_bytes = include_bytes!("kem/test-data/pk.dat");
        let sk_bytes = include_bytes!("kem/test-data/sk.dat");

        let mut serialized_pk = Vec::with_capacity(1 + kyber1024::Parameters::PUBLIC_KEY_LENGTH);
        serialized_pk.push(KeyType::Kyber1024.value());
        serialized_pk.extend_from_slice(pk_bytes);

        let mut serialized_sk = Vec::with_capacity(1 + kyber1024::Parameters::SECRET_KEY_LENGTH);
        serialized_sk.push(KeyType::Kyber1024.value());
        serialized_sk.extend_from_slice(sk_bytes);

        let pk = PublicKey::deserialize(serialized_pk.as_slice()).expect("desrialize pk");
        let sk = SecretKey::deserialize(serialized_sk.as_slice()).expect("desrialize sk");

        let reserialized_pk = pk.serialize();
        let reserialized_sk = sk.serialize();

        assert_eq!(serialized_pk, reserialized_pk.into_vec());
        assert_eq!(serialized_sk, reserialized_sk.into_vec());

        Ok(())
    }

    #[test]
    fn test_raw_kem() -> Result<()> {
        let (pk, sk) = keypair();
        let (ss1, ct) = encapsulate(&pk);
        let ss2 = decapsulate(&ct, &sk);
        assert!(ss1 == ss2);
        Ok(())
    }

    #[test]
    fn test_kyber1024_kem() -> Result<()> {
        // test data for kyber1024
        let pk_bytes = include_bytes!("kem/test-data/pk.dat");
        let sk_bytes = include_bytes!("kem/test-data/sk.dat");

        let mut serialized_pk = Vec::with_capacity(1 + kyber1024::Parameters::PUBLIC_KEY_LENGTH);
        serialized_pk.push(KeyType::Kyber1024.value());
        serialized_pk.extend_from_slice(pk_bytes);

        let mut serialized_sk = Vec::with_capacity(1 + kyber1024::Parameters::SECRET_KEY_LENGTH);
        serialized_sk.push(KeyType::Kyber1024.value());
        serialized_sk.extend_from_slice(sk_bytes);

        let pubkey = PublicKey::deserialize(serialized_pk.as_slice()).expect("deserialize pubkey");
        let secretkey =
            SecretKey::deserialize(serialized_sk.as_slice()).expect("deserialize secretkey");

        assert_eq!(pubkey.key_type, KeyType::Kyber1024);
        let (ss_for_sender, ct) = pubkey.encapsulate();
        let ss_for_recipient = secretkey.decapsulate(&ct).expect("decapsulation works");

        assert_eq!(ss_for_sender, ss_for_recipient);

        Ok(())
    }

    #[test]
    fn test_kyber1024_keypair() -> Result<()> {
        let kp = KeyPair::generate(KeyType::Kyber1024);
        let (ss_for_sender, ct) = kp.public_key.encapsulate();
        let ss_for_recipient = kp.secret_key.decapsulate(&ct).expect("decapsulation works");
        assert_eq!(ss_for_recipient, ss_for_sender);
        Ok(())
    }

    #[test]
    fn test_kyber768_keypair() -> Result<()> {
        let kp = KeyPair::generate(KeyType::Kyber768);
        let (ss_for_sender, ct) = kp.public_key.encapsulate();
        let ss_for_recipient = kp.secret_key.decapsulate(&ct).expect("decapsulation works");
        assert_eq!(ss_for_recipient, ss_for_sender);
        Ok(())
    }
}
