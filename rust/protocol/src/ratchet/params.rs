//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{IdentityKey, IdentityKeyPair, KeyPair, PublicKey};

pub struct AliceSignalProtocolParameters {
    our_identity_key_pair: IdentityKeyPair,
    our_base_key_pair: KeyPair,

    their_identity_key: IdentityKey,
    their_signed_pre_key: PublicKey,
    their_one_time_pre_key: Option<PublicKey>,
    their_ratchet_key: PublicKey,
}

impl AliceSignalProtocolParameters {
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_base_key_pair: KeyPair,
        their_identity_key: IdentityKey,
        their_signed_pre_key: PublicKey,
        their_one_time_pre_key: Option<PublicKey>,
        their_ratchet_key: PublicKey,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_base_key_pair,
            their_identity_key,
            their_signed_pre_key,
            their_one_time_pre_key,
            their_ratchet_key,
        }
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
    pub fn their_ratchet_key(&self) -> &PublicKey {
        &self.their_ratchet_key
    }
}

pub struct BobSignalProtocolParameters {
    our_identity_key_pair: IdentityKeyPair,
    our_signed_pre_key_pair: KeyPair,
    our_one_time_pre_key_pair: Option<KeyPair>,
    our_ratchet_key_pair: KeyPair,

    their_identity_key: IdentityKey,
    their_base_key: PublicKey,
}

impl BobSignalProtocolParameters {
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_signed_pre_key_pair: KeyPair,
        our_one_time_pre_key_pair: Option<KeyPair>,
        our_ratchet_key_pair: KeyPair,
        their_identity_key: IdentityKey,
        their_base_key: PublicKey,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_signed_pre_key_pair,
            our_one_time_pre_key_pair,
            our_ratchet_key_pair,
            their_identity_key,
            their_base_key,
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
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    #[inline]
    pub fn their_base_key(&self) -> &PublicKey {
        &self.their_base_key
    }
}
