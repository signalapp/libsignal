//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::state::{PreKeyId, SignedPreKeyId};
use crate::{kem, DeviceId, IdentityKey, KyberPreKeyId, PublicKey, Result};
use std::clone::Clone;

#[derive(Clone)]
struct SignedPreKey {
    id: SignedPreKeyId,
    public_key: PublicKey,
    signature: Vec<u8>,
}

impl SignedPreKey {
    fn new(id: SignedPreKeyId, public_key: PublicKey, signature: Vec<u8>) -> Self {
        Self {
            id,
            public_key,
            signature,
        }
    }
}

#[derive(Clone)]
struct KyberPreKey {
    id: KyberPreKeyId,
    public_key: kem::PublicKey,
    signature: Vec<u8>,
}

impl KyberPreKey {
    fn new(id: KyberPreKeyId, public_key: kem::PublicKey, signature: Vec<u8>) -> Self {
        Self {
            id,
            public_key,
            signature,
        }
    }
}

#[derive(Clone)]
pub struct PreKeyBundle {
    registration_id: u32,
    device_id: DeviceId,
    pre_key_id: Option<PreKeyId>,
    pre_key_public: Option<PublicKey>,
    ec_signed_pre_key: SignedPreKey,
    identity_key: IdentityKey,
    // Optional to support older clients
    // TODO: remove optionality once the transition is over
    kyber_pre_key: Option<KyberPreKey>,
}

impl PreKeyBundle {
    pub fn new(
        registration_id: u32,
        device_id: DeviceId,
        pre_key: Option<(PreKeyId, PublicKey)>,
        signed_pre_key_id: SignedPreKeyId,
        signed_pre_key_public: PublicKey,
        signed_pre_key_signature: Vec<u8>,
        identity_key: IdentityKey,
    ) -> Result<Self> {
        let (pre_key_id, pre_key_public) = match pre_key {
            None => (None, None),
            Some((id, key)) => (Some(id), Some(key)),
        };

        let ec_signed_pre_key = SignedPreKey::new(
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
        );

        Ok(Self {
            registration_id,
            device_id,
            pre_key_id,
            pre_key_public,
            ec_signed_pre_key,
            identity_key,
            kyber_pre_key: None,
        })
    }

    pub fn with_kyber_pre_key(
        mut self,
        pre_key_id: KyberPreKeyId,
        public_key: kem::PublicKey,
        signature: Vec<u8>,
    ) -> Self {
        self.kyber_pre_key = Some(KyberPreKey::new(pre_key_id, public_key, signature));
        self
    }

    pub fn registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    pub fn device_id(&self) -> Result<DeviceId> {
        Ok(self.device_id)
    }

    pub fn pre_key_id(&self) -> Result<Option<PreKeyId>> {
        Ok(self.pre_key_id)
    }

    pub fn pre_key_public(&self) -> Result<Option<PublicKey>> {
        Ok(self.pre_key_public)
    }

    pub fn signed_pre_key_id(&self) -> Result<SignedPreKeyId> {
        Ok(self.ec_signed_pre_key.id)
    }

    pub fn signed_pre_key_public(&self) -> Result<PublicKey> {
        Ok(self.ec_signed_pre_key.public_key)
    }

    pub fn signed_pre_key_signature(&self) -> Result<&[u8]> {
        Ok(self.ec_signed_pre_key.signature.as_ref())
    }

    pub fn identity_key(&self) -> Result<&IdentityKey> {
        Ok(&self.identity_key)
    }

    pub fn has_kyber_pre_key(&self) -> bool {
        self.kyber_pre_key.is_some()
    }

    pub fn kyber_pre_key_id(&self) -> Result<Option<KyberPreKeyId>> {
        Ok(self.kyber_pre_key.as_ref().map(|pre_key| pre_key.id))
    }

    pub fn kyber_pre_key_public(&self) -> Result<Option<&kem::PublicKey>> {
        Ok(self
            .kyber_pre_key
            .as_ref()
            .map(|pre_key| &pre_key.public_key))
    }

    pub fn kyber_pre_key_signature(&self) -> Result<Option<&[u8]>> {
        Ok(self
            .kyber_pre_key
            .as_ref()
            .map(|pre_key| pre_key.signature.as_ref()))
    }
}
