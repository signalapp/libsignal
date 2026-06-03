//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Long-term Ristretto key pair owned by an account, used as a binding identity
//! across ZK credentials issued to that account (currently
//! [`crate::avatars::AvatarUploadCredential`]).
//!
//! Distinct from the account's curve25519 identity key. The public key is a wire
//! type stored by the server; the secret key is a wire type that must be synced
//! to linked devices.

// We use upper-case variable names for curve points by convention.
#![allow(non_snake_case)]

use curve25519_dalek_signal::ristretto::RistrettoPoint;
use curve25519_dalek_signal::scalar::Scalar;
use partial_default::PartialDefault;
use poksho::ShoApi;
use serde::{Deserialize, Serialize};
use zkcredential::sho::ShoExt as _;

use crate::RandomnessBytes;
use crate::common::serialization::ReservedByte;

#[derive(Clone, Deserialize, PartialDefault)]
#[serde(from = "ZkCredentialPrivateKey")]
pub struct ZkCredentialKeyPair {
    secret: Scalar,
    public: RistrettoPoint,
}

/// The serialized form of [`ZkCredentialKeyPair`].
///
/// This stores only the secret scalar. The public key is derived when the key
/// pair is loaded, matching the surrounding key-pair types in `zkcredential`.
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
struct ZkCredentialPrivateKey {
    reserved: ReservedByte,
    secret: Scalar,
}

impl ZkCredentialKeyPair {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        let mut sho = poksho::ShoHmacSha256::new(b"20260520_Signal_ZkCredentialKeyPair_Generate");
        sho.absorb_and_ratchet(&randomness);
        let secret = sho.get_scalar();
        let public = RistrettoPoint::mul_base(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> ZkCredentialPublicKey {
        ZkCredentialPublicKey {
            reserved: Default::default(),
            public: self.public,
        }
    }

    pub(crate) fn secret(&self) -> Scalar {
        self.secret
    }
}

impl From<ZkCredentialPrivateKey> for ZkCredentialKeyPair {
    fn from(value: ZkCredentialPrivateKey) -> Self {
        let ZkCredentialPrivateKey {
            reserved: _,
            secret,
        } = value;
        let public = RistrettoPoint::mul_base(&secret);
        Self { secret, public }
    }
}

impl Serialize for ZkCredentialKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ZkCredentialPrivateKey {
            reserved: Default::default(),
            secret: self.secret,
        }
        .serialize(serializer)
    }
}

/// The public half of a [`ZkCredentialKeyPair`].
///
/// Serialized wire format: reserved byte + 32-byte compressed Ristretto point.
#[derive(Clone, Copy, Serialize, Deserialize, PartialDefault)]
pub struct ZkCredentialPublicKey {
    reserved: ReservedByte,
    public: RistrettoPoint,
}

impl ZkCredentialPublicKey {
    pub(crate) fn point(&self) -> RistrettoPoint {
        self.public
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RANDOMNESS_LEN;

    #[test]
    fn generate_is_deterministic() {
        let r: RandomnessBytes = [0x7Au8; RANDOMNESS_LEN];
        let a = ZkCredentialKeyPair::generate(r);
        let b = ZkCredentialKeyPair::generate(r);
        assert_eq!(a.secret, b.secret);
        assert_eq!(a.public, b.public);
    }

    #[test]
    fn roundtrip_keypair() {
        let r: RandomnessBytes = [0x11u8; RANDOMNESS_LEN];
        let kp = ZkCredentialKeyPair::generate(r);
        let bytes = crate::serialize(&kp);
        let parsed: ZkCredentialKeyPair = crate::deserialize(&bytes).expect("roundtrip");
        assert_eq!(kp.secret, parsed.secret);
        assert_eq!(kp.public, parsed.public);
    }

    #[test]
    fn roundtrip_public_key() {
        let r: RandomnessBytes = [0x22u8; RANDOMNESS_LEN];
        let pk = ZkCredentialKeyPair::generate(r).public_key();
        let bytes = crate::serialize(&pk);
        let parsed: ZkCredentialPublicKey = crate::deserialize(&bytes).expect("roundtrip");
        assert_eq!(pk.public, parsed.public);
    }

    #[test]
    fn public_key_derives_from_secret() {
        let r: RandomnessBytes = [0x33u8; RANDOMNESS_LEN];
        let kp = ZkCredentialKeyPair::generate(r);
        let pk = kp.public_key();
        assert_eq!(RistrettoPoint::mul_base(&kp.secret), pk.public);
    }
}
