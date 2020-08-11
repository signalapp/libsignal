use crate::curve;
use crate::IdentityKey;

use crate::error::{Result, SignalProtocolError};
use crate::state::{PreKeyId, SignedPreKeyId};

#[derive(Debug)]
pub struct PreKeyBundle {
    registration_id: u32,
    device_id: u32,
    pre_key_id: Option<PreKeyId>,
    pre_key_public: Option<curve::PublicKey>,
    signed_pre_key_id: SignedPreKeyId,
    signed_pre_key_public: curve::PublicKey,
    signed_pre_key_signature: Vec<u8>,
    identity_key: IdentityKey,
}

impl PreKeyBundle {
    pub fn new(
        registration_id: u32,
        device_id: u32,
        pre_key_id: Option<PreKeyId>,
        pre_key_public: Option<curve::PublicKey>,
        signed_pre_key_id: SignedPreKeyId,
        signed_pre_key_public: curve::PublicKey,
        signed_pre_key_signature: Vec<u8>,
        identity_key: IdentityKey,
    ) -> Result<Self> {
        if pre_key_public.is_some() != pre_key_id.is_some() {
            return Err(SignalProtocolError::InvalidPreKeyBundle);
        }

        Ok(Self {
            registration_id,
            device_id,
            pre_key_id,
            pre_key_public,
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
            identity_key,
        })
    }

    pub fn registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    pub fn device_id(&self) -> Result<u32> {
        Ok(self.device_id)
    }

    pub fn pre_key_id(&self) -> Result<Option<PreKeyId>> {
        Ok(self.pre_key_id)
    }

    pub fn pre_key_public(&self) -> Result<Option<curve::PublicKey>> {
        Ok(self.pre_key_public)
    }

    pub fn signed_pre_key_id(&self) -> Result<SignedPreKeyId> {
        Ok(self.signed_pre_key_id)
    }

    pub fn signed_pre_key_public(&self) -> Result<curve::PublicKey> {
        Ok(self.signed_pre_key_public)
    }

    pub fn signed_pre_key_signature(&self) -> Result<&[u8]> {
        Ok(self.signed_pre_key_signature.as_ref())
    }

    pub fn identity_key(&self) -> Result<&IdentityKey> {
        Ok(&self.identity_key)
    }
}
