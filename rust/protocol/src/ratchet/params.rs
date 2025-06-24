//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{kem, IdentityKey, IdentityKeyPair, KeyPair, PublicKey};
use pswoosh::keys::{PublicSwooshKey, SwooshKeyPair};

#[derive(Clone, Copy)]
pub enum UsePQRatchet {
    No,
    Yes,
}

impl From<bool> for UsePQRatchet {
    fn from(value: bool) -> Self {
        if value {
            UsePQRatchet::Yes
        } else {
            UsePQRatchet::No
        }
    }
}

pub struct AliceSignalProtocolParameters {
    our_identity_key_pair: IdentityKeyPair,
    our_base_key_pair: KeyPair,
    our_base_swoosh_key_pair: Option<SwooshKeyPair>,

    their_identity_key: IdentityKey,
    their_signed_pre_key: PublicKey,
    their_one_time_pre_key: Option<PublicKey>,
    their_ratchet_key: PublicKey,
    their_kyber_pre_key: Option<kem::PublicKey>,
    their_swoosh_pre_key: Option<PublicSwooshKey>,

    // Swoosh quantum-resistant keys
    our_swoosh_key_pair: Option<SwooshKeyPair>,
    their_swoosh_ratchet_key: Option<PublicSwooshKey>,

    use_pq_ratchet: UsePQRatchet,
}

impl AliceSignalProtocolParameters {
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_base_key_pair: KeyPair,
        our_base_swoosh_key_pair: Option<SwooshKeyPair>,
        their_identity_key: IdentityKey,
        their_signed_pre_key: PublicKey,
        their_ratchet_key: PublicKey,
        their_swoosh_pre_key: Option<PublicSwooshKey>,
        their_swoosh_ratchet_key: Option<PublicSwooshKey>,
        use_pq_ratchet: UsePQRatchet,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_base_key_pair,
            our_base_swoosh_key_pair,
            their_identity_key,
            their_signed_pre_key,
            their_one_time_pre_key: None,
            their_ratchet_key,
            their_kyber_pre_key: None,
            their_swoosh_pre_key,
            our_swoosh_key_pair: None,
            their_swoosh_ratchet_key,
            use_pq_ratchet,
        }
    }

    pub fn set_their_one_time_pre_key(&mut self, ec_public: PublicKey) {
        self.their_one_time_pre_key = Some(ec_public);
    }

    pub fn with_their_one_time_pre_key(mut self, ec_public: PublicKey) -> Self {
        self.set_their_one_time_pre_key(ec_public);
        self
    }

    pub fn set_their_kyber_pre_key(&mut self, kyber_public: &kem::PublicKey) {
        self.their_kyber_pre_key = Some(kyber_public.clone());
    }

    pub fn set_their_swoosh_pre_key(&mut self, swoosh_public: &pswoosh::keys::PublicSwooshKey) {
        self.their_swoosh_pre_key = Some(swoosh_public.clone());
    }

    pub fn with_their_kyber_pre_key(mut self, kyber_public: &kem::PublicKey) -> Self {
        self.set_their_kyber_pre_key(kyber_public);
        self
    }

    pub fn set_our_swoosh_key_pair(&mut self, key_pair: SwooshKeyPair) {
        self.our_swoosh_key_pair = Some(key_pair);
    }

    pub fn with_our_swoosh_key_pair(mut self, key_pair: SwooshKeyPair) -> Self {
        self.set_our_swoosh_key_pair(key_pair);
        self
    }

    pub fn set_their_swoosh_ratchet_key(&mut self, public_key: PublicSwooshKey) {
        self.their_swoosh_ratchet_key = Some(public_key);
    }

    pub fn with_their_swoosh_ratchet_key(mut self, public_key: PublicSwooshKey) -> Self {
        self.set_their_swoosh_ratchet_key(public_key);
        self
    }

    #[inline]
    pub fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    #[inline]
    pub fn our_base_key_pair(&self) -> &KeyPair {
        &self.our_base_key_pair
    }

    #[inline]
    pub fn our_base_swoosh_key_pair(&self) -> Option<&SwooshKeyPair> {
        self.our_base_swoosh_key_pair.as_ref()
    }

    #[inline]
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    #[inline]
    pub fn their_signed_pre_key(&self) -> &PublicKey {
        &self.their_signed_pre_key
    }

    #[inline]
    pub fn their_one_time_pre_key(&self) -> Option<&PublicKey> {
        self.their_one_time_pre_key.as_ref()
    }

    #[inline]
    pub fn their_kyber_pre_key(&self) -> Option<&kem::PublicKey> {
        self.their_kyber_pre_key.as_ref()
    }

    #[inline]
    pub fn their_ratchet_key(&self) -> &PublicKey {
        &self.their_ratchet_key
    }

    #[inline]
    pub fn use_pq_ratchet(&self) -> UsePQRatchet {
        self.use_pq_ratchet
    }

    #[inline]
    pub fn our_swoosh_key_pair(&self) -> Option<&SwooshKeyPair> {
        self.our_swoosh_key_pair.as_ref()
    }

    #[inline]
    pub fn their_swoosh_ratchet_key(&self) -> Option<&PublicSwooshKey> {
        self.their_swoosh_ratchet_key.as_ref()
    }

    #[inline]
    pub fn their_swoosh_pre_key(&self) -> Option<&PublicSwooshKey> {
        self.their_swoosh_pre_key.as_ref()
    }
}

pub struct BobSignalProtocolParameters<'a> {
    our_identity_key_pair: IdentityKeyPair,
    our_signed_pre_key_pair: KeyPair,
    our_one_time_pre_key_pair: Option<KeyPair>,
    our_ratchet_key_pair: KeyPair,
    // Optional, we are Kyber-aware, but there may be no kyber prekey id communicated from Alice
    our_kyber_pre_key_pair: Option<kem::KeyPair>,

    their_identity_key: IdentityKey,
    their_base_key: PublicKey,
    their_swoosh_pre_key: Option<PublicSwooshKey>,

    // Swoosh quantum-resistant keys
    our_ratchet_swoosh_key_pair: Option<SwooshKeyPair>,
    their_swoosh_ratchet_key: Option<PublicSwooshKey>,
    their_kyber_ciphertext: Option<&'a kem::SerializedCiphertext>,

    use_pq_ratchet: UsePQRatchet,
}

impl<'a> BobSignalProtocolParameters<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_signed_pre_key_pair: KeyPair,
        our_one_time_pre_key_pair: Option<KeyPair>,
        our_ratchet_key_pair: KeyPair,
        our_ratchet_swoosh_key_pair: Option<SwooshKeyPair>,
        our_kyber_pre_key_pair: Option<kem::KeyPair>,
        their_identity_key: IdentityKey,
        their_base_key: PublicKey,
        their_kyber_ciphertext: Option<&'a kem::SerializedCiphertext>,
        use_pq_ratchet: UsePQRatchet,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_signed_pre_key_pair,
            our_one_time_pre_key_pair,
            our_ratchet_key_pair,
            our_kyber_pre_key_pair,
            their_identity_key,
            their_base_key,
            our_ratchet_swoosh_key_pair,
            their_swoosh_ratchet_key: None,
            their_swoosh_pre_key: None,
            their_kyber_ciphertext,
            use_pq_ratchet,
        }
    }

    pub fn set_our_swoosh_key_pair(&mut self, key_pair: SwooshKeyPair) {
        self.our_ratchet_swoosh_key_pair = Some(key_pair);
    }

    pub fn with_our_swoosh_key_pair(mut self, key_pair: SwooshKeyPair) -> Self {
        self.set_our_swoosh_key_pair(key_pair);
        self
    }

    pub fn set_their_swoosh_pre_key(&mut self, public_key: PublicSwooshKey) {
        self.their_swoosh_pre_key = Some(public_key);
    }

    pub fn with_their_swoosh_pre_key(mut self, public_key: PublicSwooshKey) -> Self {
        self.set_their_swoosh_pre_key(public_key);
        self
    }

    pub fn set_their_swoosh_ratchet_key(&mut self, public_key: PublicSwooshKey) {
        self.their_swoosh_ratchet_key = Some(public_key);
    }

    pub fn with_their_swoosh_ratchet_key(mut self, public_key: PublicSwooshKey) -> Self {
        self.set_their_swoosh_ratchet_key(public_key);
        self
    }

    #[inline]
    pub fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    #[inline]
    pub fn our_signed_pre_key_pair(&self) -> &KeyPair {
        &self.our_signed_pre_key_pair
    }

    #[inline]
    pub fn our_one_time_pre_key_pair(&self) -> Option<&KeyPair> {
        self.our_one_time_pre_key_pair.as_ref()
    }

    #[inline]
    pub fn our_ratchet_key_pair(&self) -> &KeyPair {
        &self.our_ratchet_key_pair
    }

    #[inline]
    pub fn our_ratchet_swoosh_key_pair(&self) -> Option<&SwooshKeyPair> {
        self.our_ratchet_swoosh_key_pair.as_ref()
    }

    #[inline]
    pub fn our_kyber_pre_key_pair(&self) -> &Option<kem::KeyPair> {
        &self.our_kyber_pre_key_pair
    }

    #[inline]
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    #[inline]
    pub fn their_base_key(&self) -> &PublicKey {
        &self.their_base_key
    }

    #[inline]
    pub fn their_kyber_ciphertext(&self) -> Option<&kem::SerializedCiphertext> {
        self.their_kyber_ciphertext
    }

    #[inline]
    pub fn use_pq_ratchet(&self) -> UsePQRatchet {
        self.use_pq_ratchet
    }

    #[inline]
    pub fn our_swoosh_key_pair(&self) -> Option<&SwooshKeyPair> {
        self.our_ratchet_swoosh_key_pair.as_ref()
    }

    #[inline]
    pub fn their_swoosh_pre_key(&self) -> Option<&PublicSwooshKey> {
        self.their_swoosh_pre_key.as_ref()
    }

    #[inline]
    pub fn their_swoosh_ratchet_key(&self) -> Option<&PublicSwooshKey> {
        self.their_swoosh_ratchet_key.as_ref()
    }
}
