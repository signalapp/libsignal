//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::state::{PreKeyId, SignedPreKeyId};
use crate::{kem, DeviceId, IdentityKey, KyberPreKeyId, PublicKey, Result, SignalProtocolError};
use std::clone::Clone;
use std::convert::{TryFrom, TryInto};

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

// Represents the raw contents of the pre-key bundle without any notion of required/optional
// fields.
// Can be used as a "builder" for PreKeyBundle, in which case all the validation will happen in
// PreKeyBundle::new.
pub struct PreKeyBundleContent {
    pub registration_id: Option<u32>,
    pub device_id: Option<DeviceId>,
    pub pre_key_id: Option<PreKeyId>,
    pub pre_key_public: Option<PublicKey>,
    pub ec_pre_key_id: Option<SignedPreKeyId>,
    pub ec_pre_key_public: Option<PublicKey>,
    pub ec_pre_key_signature: Option<Vec<u8>>,
    pub identity_key: Option<IdentityKey>,
    pub kyber_pre_key_id: Option<KyberPreKeyId>,
    pub kyber_pre_key_public: Option<kem::PublicKey>,
    pub kyber_pre_key_signature: Option<Vec<u8>>,
}

impl From<PreKeyBundle> for PreKeyBundleContent {
    fn from(bundle: PreKeyBundle) -> Self {
        Self {
            registration_id: Some(bundle.registration_id),
            device_id: Some(bundle.device_id),
            pre_key_id: bundle.pre_key_id,
            pre_key_public: bundle.pre_key_public,
            ec_pre_key_id: Some(bundle.ec_signed_pre_key.id),
            ec_pre_key_public: Some(bundle.ec_signed_pre_key.public_key),
            ec_pre_key_signature: Some(bundle.ec_signed_pre_key.signature),
            identity_key: Some(bundle.identity_key),
            kyber_pre_key_id: bundle.kyber_pre_key.as_ref().map(|kyber| kyber.id),
            kyber_pre_key_public: bundle
                .kyber_pre_key
                .as_ref()
                .map(|kyber| kyber.public_key.clone()),
            kyber_pre_key_signature: bundle
                .kyber_pre_key
                .as_ref()
                .map(|kyber| kyber.signature.clone()),
        }
    }
}

impl TryFrom<PreKeyBundleContent> for PreKeyBundle {
    type Error = SignalProtocolError;

    fn try_from(content: PreKeyBundleContent) -> Result<Self> {
        let mut bundle = PreKeyBundle::new(
            content.registration_id.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("registration_id is required".to_string())
            })?,
            content.device_id.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("device_id is required".to_string())
            })?,
            content
                .pre_key_id
                .and_then(|id| content.pre_key_public.map(|public| (id, public))),
            content.ec_pre_key_id.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("signed_pre_key_id is required".to_string())
            })?,
            content.ec_pre_key_public.ok_or_else(|| {
                SignalProtocolError::InvalidArgument(
                    "signed_pre_key_public is required".to_string(),
                )
            })?,
            content.ec_pre_key_signature.ok_or_else(|| {
                SignalProtocolError::InvalidArgument(
                    "signed_pre_key_signature is required".to_string(),
                )
            })?,
            content.identity_key.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("identity_key is required".to_string())
            })?,
        )?;

        fn zip3<T, U, V>(x: Option<T>, y: Option<U>, z: Option<V>) -> Option<(T, U, V)> {
            x.zip(y).zip(z).map(|((x, y), z)| (x, y, z))
        }

        if let Some((kyber_id, kyber_public, kyber_sig)) = zip3(
            content.kyber_pre_key_id,
            content.kyber_pre_key_public,
            content.kyber_pre_key_signature,
        ) {
            bundle = bundle.with_kyber_pre_key(kyber_id, kyber_public, kyber_sig);
        }
        Ok(bundle)
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

    pub fn modify<F>(self, modify: F) -> Result<Self>
    where
        F: FnOnce(&mut PreKeyBundleContent),
    {
        let mut content = self.into();
        modify(&mut content);
        content.try_into()
    }
}
