//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub use super::super::curve::{KeyPair as CurveKeyPair, PublicKey as CurvePublicKey};
pub use super::super::{IdentityKey, IdentityKeyPair};

pub struct AliceSignalProtocolParameters {
    our_identity_key_pair: IdentityKeyPair,
    our_base_key_pair: CurveKeyPair,

    their_identity_key: IdentityKey,
    their_signed_pre_key: CurvePublicKey,
    their_one_time_pre_key: Option<CurvePublicKey>,
    their_ratchet_key: CurvePublicKey,
}

impl AliceSignalProtocolParameters {
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_base_key_pair: CurveKeyPair,
        their_identity_key: IdentityKey,
        their_signed_pre_key: CurvePublicKey,
        their_one_time_pre_key: Option<CurvePublicKey>,
        their_ratchet_key: CurvePublicKey,
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
    pub fn our_base_key_pair(&self) -> &CurveKeyPair {
        &self.our_base_key_pair
    }

    #[inline]
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    #[inline]
    pub fn their_signed_pre_key(&self) -> &CurvePublicKey {
        &self.their_signed_pre_key
    }

    #[inline]
    pub fn their_one_time_pre_key(&self) -> Option<&CurvePublicKey> {
        self.their_one_time_pre_key.as_ref()
    }

    #[inline]
    pub fn their_ratchet_key(&self) -> &CurvePublicKey {
        &self.their_ratchet_key
    }
}

pub struct BobSignalProtocolParameters {
    our_identity_key_pair: IdentityKeyPair,
    our_signed_pre_key_pair: CurveKeyPair,
    our_one_time_pre_key_pair: Option<CurveKeyPair>,
    our_ratchet_key_pair: CurveKeyPair,

    their_identity_key: IdentityKey,
    their_base_key: CurvePublicKey,
}

impl BobSignalProtocolParameters {
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_signed_pre_key_pair: CurveKeyPair,
        our_one_time_pre_key_pair: Option<CurveKeyPair>,
        our_ratchet_key_pair: CurveKeyPair,
        their_identity_key: IdentityKey,
        their_base_key: CurvePublicKey,
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
    pub fn our_signed_pre_key_pair(&self) -> &CurveKeyPair {
        &self.our_signed_pre_key_pair
    }

    #[inline]
    pub fn our_one_time_pre_key_pair(&self) -> Option<&CurveKeyPair> {
        self.our_one_time_pre_key_pair.as_ref()
    }

    #[inline]
    pub fn our_ratchet_key_pair(&self) -> &CurveKeyPair {
        &self.our_ratchet_key_pair
    }

    #[inline]
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    #[inline]
    pub fn their_base_key(&self) -> &CurvePublicKey {
        &self.their_base_key
    }
}
