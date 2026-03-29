//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_core::ProtocolAddress;

use crate::{IdentityKey, IdentityKeyPair, KeyPair, PublicKey, kem, SessionRecord, SignalMessage, Result};
use rand::rand_core::{CryptoRng};

pub struct AliceSignalProtocolParameters {
    our_identity_key_pair: IdentityKeyPair,
    our_base_key_pair: KeyPair,

    their_identity_key: IdentityKey,
    their_signed_pre_key: PublicKey,
    their_one_time_pre_key: Option<PublicKey>,
    their_ratchet_key: PublicKey,
    their_kyber_pre_key: kem::PublicKey,
}

impl AliceSignalProtocolParameters {
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_base_key_pair: KeyPair,
        their_identity_key: IdentityKey,
        their_signed_pre_key: PublicKey,
        their_ratchet_key: PublicKey,
        their_kyber_pre_key: kem::PublicKey,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_base_key_pair,
            their_identity_key,
            their_signed_pre_key,
            their_one_time_pre_key: None,
            their_ratchet_key,
            their_kyber_pre_key,
        }
    }

    pub fn set_their_one_time_pre_key(&mut self, ec_public: PublicKey) {
        self.their_one_time_pre_key = Some(ec_public);
    }

    pub fn with_their_one_time_pre_key(mut self, ec_public: PublicKey) -> Self {
        self.set_their_one_time_pre_key(ec_public);
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
    pub fn their_kyber_pre_key(&self) -> &kem::PublicKey {
        &self.their_kyber_pre_key
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
    our_kyber_pre_key_pair: kem::KeyPair,

    their_identity_key: IdentityKey,
    their_base_key: PublicKey,
    their_kyber_ciphertext: &'a kem::SerializedCiphertext,
    remote_address: &'a ProtocolAddress,
    csprng: &'a dyn CryptoRng,
    decrypt_message_with_record: &'a dyn Fn(
        &ProtocolAddress,
        &mut SessionRecord,
        &SignalMessage,
        u8,
        &'a dyn CryptoRng,
    ) -> Result<Vec<u8>>,
}

impl<'a> BobSignalProtocolParameters<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_signed_pre_key_pair: KeyPair,
        our_one_time_pre_key_pair: Option<KeyPair>,
        our_ratchet_key_pair: KeyPair,
        our_kyber_pre_key_pair: kem::KeyPair,
        their_identity_key: IdentityKey,
        their_base_key: PublicKey,
        their_kyber_ciphertext: &'a kem::SerializedCiphertext,
        remote_address: &'a ProtocolAddress,
        csprng: &'a dyn CryptoRng,
        decrypt_message_with_record: &'a dyn Fn(
            &ProtocolAddress,
            &mut SessionRecord,
            &SignalMessage,
            u8,
            &'a dyn CryptoRng,
        ) -> Result<Vec<u8>>,
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
            remote_address,
            csprng,
            decrypt_message_with_record: decrypt_message_with_record,
        }
    }

    #[inline]
    pub fn decrypt_message_with_record(
        &self,
        remote_address: &ProtocolAddress,
        session_record: &mut SessionRecord,
        ciphertext: &SignalMessage,
        message_version: u8,
    ) -> Result<Vec<u8>> {
        (self.decrypt_message_with_record)(
            remote_address,
            session_record,
            ciphertext,
            message_version,
            self.csprng,
        )
    }

    #[inline]
    pub fn remote_address(&self) -> &ProtocolAddress {
        &self.remote_address
    }

    #[inline]
    pub fn csprng(&self) -> &dyn CryptoRng {
        self.csprng
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
    pub fn our_kyber_pre_key_pair(&self) -> &kem::KeyPair {
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
    pub fn their_kyber_ciphertext(&self) -> &kem::SerializedCiphertext {
        self.their_kyber_ciphertext
    }
}
