//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Long-term Ristretto key pair owned by an account, used as a binding identity
//! across ZK credentials issued to that account (currently
//! [`crate::avatars::AvatarUploadCredential`]).
//!
//! The secret key is a pair of scalars `(a1, a2)`, generated deterministically from a 32 bytes
//! seed; the public key is `A = a1*G_a1 + a2*G_a2`.
//! Distinct from the account's curve25519 identity key. The public key is a wire
//! type stored by the server; the secret key is a wire type that must be synced
//! to linked devices.
//!
//! Internally this wraps [`zkcredential::attributes::KeyPair`] to reuse its `(a1, a2)` / `A`
//! structure and domain-separated generators, but it deliberately does **not** expose that type's
//! CPZ `encrypt`/`decrypt` methods: this key is used only for its scalar/point structure, never to
//! encrypt attributes.

// We use upper-case variable names for curve points by convention.
#![allow(non_snake_case)]

use std::sync::OnceLock;

use curve25519_dalek_signal::ristretto::RistrettoPoint;
use curve25519_dalek_signal::scalar::Scalar;
use partial_default::PartialDefault;
use poksho::ShoApi;
use serde::{Deserialize, Serialize};
use zkcredential::attributes::{Domain, KeyPair, PublicKey, derive_default_generator_points};

use crate::RandomnessBytes;
use crate::common::serialization::ReservedByte;

/// Domain for the account ZK credential key.
///
/// `G_a()` supplies the two independent generators `(G_a1, G_a2)` for the
/// public key `A = a1*G_a1 + a2*G_a2`. The `Attribute` type is required by the
/// trait but isn't really used here: this key never performs CPZ attribute
/// encryption.
pub struct ZkCredentialKeyDomain;

impl Domain for ZkCredentialKeyDomain {
    type Attribute = [RistrettoPoint; 2];

    const ID: &'static str = "Signal_ZkCredentialKey_20260602";

    fn G_a() -> [RistrettoPoint; 2] {
        static STORAGE: OnceLock<[RistrettoPoint; 2]> = OnceLock::new();
        *derive_default_generator_points::<Self>(&STORAGE)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct ZkCredentialKeyPair {
    reserved: ReservedByte,
    inner: KeyPair<ZkCredentialKeyDomain>,
}

impl ZkCredentialKeyPair {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        let mut sho = poksho::ShoHmacSha256::new(b"20260520_Signal_ZkCredentialKeyPair_Generate");
        sho.absorb_and_ratchet(&randomness);
        Self {
            reserved: Default::default(),
            inner: KeyPair::derive_from(&mut sho),
        }
    }

    pub fn public_key(&self) -> ZkCredentialPublicKey {
        ZkCredentialPublicKey {
            reserved: Default::default(),
            inner: self.inner.public_key,
        }
    }

    /// The two secret scalars `(a1, a2)`.
    pub(crate) fn secrets(&self) -> (Scalar, Scalar) {
        (self.inner.a1, self.inner.a2)
    }
}

/// The public half of a [`ZkCredentialKeyPair`].
///
/// Serialized wire format: reserved byte + 32-byte compressed Ristretto point (`A`).
#[derive(Clone, Copy, Serialize, Deserialize, PartialDefault)]
pub struct ZkCredentialPublicKey {
    reserved: ReservedByte,
    inner: PublicKey<ZkCredentialKeyDomain>,
}

impl ZkCredentialPublicKey {
    pub(crate) fn point(&self) -> RistrettoPoint {
        self.inner.A
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
        assert_eq!(a.secrets(), b.secrets());
        assert_eq!(a.public_key().point(), b.public_key().point());
    }

    #[test]
    fn roundtrip_keypair() {
        let r: RandomnessBytes = [0x11u8; RANDOMNESS_LEN];
        let kp = ZkCredentialKeyPair::generate(r);
        let bytes = crate::serialize(&kp);
        let parsed: ZkCredentialKeyPair = crate::deserialize(&bytes).expect("roundtrip");
        assert_eq!(kp.secrets(), parsed.secrets());
        assert_eq!(kp.public_key().point(), parsed.public_key().point());
    }

    #[test]
    fn roundtrip_public_key() {
        let r: RandomnessBytes = [0x22u8; RANDOMNESS_LEN];
        let pk = ZkCredentialKeyPair::generate(r).public_key();
        let bytes = crate::serialize(&pk);
        let parsed: ZkCredentialPublicKey = crate::deserialize(&bytes).expect("roundtrip");
        assert_eq!(pk.point(), parsed.point());
    }

    #[test]
    fn public_key_derives_from_secrets() {
        let r: RandomnessBytes = [0x33u8; RANDOMNESS_LEN];
        let kp = ZkCredentialKeyPair::generate(r);
        let (a1, a2) = kp.secrets();
        let [G_a1, G_a2] = ZkCredentialKeyDomain::G_a();
        assert_eq!(a1 * G_a1 + a2 * G_a2, kp.public_key().point());
    }
}
