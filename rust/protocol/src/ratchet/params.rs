//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{kem, IdentityKey, IdentityKeyPair, KeyPair, PublicKey};

pub struct AliceSignalProtocolParameters {
    our_identity_key_pair: IdentityKeyPair,
    our_base_key_pair: KeyPair,

    their_identity_key: IdentityKey,
    their_signed_pre_key: PublicKey,
    their_one_time_pre_key: Option<PublicKey>,
    their_ratchet_key: PublicKey,
    their_kyber_pre_key: Option<kem::PublicKey>,
}

impl AliceSignalProtocolParameters {
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_base_key_pair: KeyPair,
        their_identity_key: IdentityKey,
        their_signed_pre_key: PublicKey,
        their_ratchet_key: PublicKey,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_base_key_pair,
            their_identity_key,
            their_signed_pre_key,
            their_one_time_pre_key: None,
            their_ratchet_key,
            their_kyber_pre_key: None,
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

    pub fn with_their_kyber_pre_key(mut self, kyber_public: &kem::PublicKey) -> Self {
        self.set_their_kyber_pre_key(kyber_public);
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
    their_kyber_ciphertext: Option<&'a kem::SerializedCiphertext>,
}

impl<'a> BobSignalProtocolParameters<'a> {
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_signed_pre_key_pair: KeyPair,
        our_one_time_pre_key_pair: Option<KeyPair>,
        our_ratchet_key_pair: KeyPair,
        our_kyber_pre_key_pair: Option<kem::KeyPair>,
        their_identity_key: IdentityKey,
        their_base_key: PublicKey,
        their_kyber_ciphertext: Option<&'a kem::SerializedCiphertext>,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_signed_pre_key_pair,
            our_one_time_pre_key_pair,
            our_ratchet_key_pair,
            our_kyber_pre_key_pair,
            their_identity_key,
            their_base_key,
            their_kyber_ciphertext,
        }
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
}
