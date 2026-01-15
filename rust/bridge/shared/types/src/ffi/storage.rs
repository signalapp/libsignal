//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_bridge_macros::bridge_callbacks;
use uuid::Uuid;

use super::*;
use crate::ffi;
use crate::support::{ResultLike, WithContext};

/// A wrapper struct so we can implement e.g. [`KyberPreKeyStore`] for all
/// [`BridgeKyberPreKeyStore`]s.
///
/// Trying to do so directly would violate the [orphan rule][], because rustc doesn't know
/// `BridgeKyberPreKeyStore` is only implemented by a closed set of types defined in this crate.
///
/// [orphan rule]: https://doc.rust-lang.org/book/ch20-02-advanced-traits.html#implementing-external-traits-with-the-newtype-pattern
pub struct BridgedStore<T>(pub T);

/// A bridge-friendly version of [`IdentityKeyStore`].
#[bridge_callbacks(jni = false, node = false)]
pub trait BridgeIdentityKeyStore {
    // We ask for just the private key because IdentityKeyPair isn't a single bridge_handle; it's a
    // pair of objects. This is easier to bridge.
    fn get_local_identity_private_key(&self) -> Result<PrivateKey, SignalProtocolError>;
    fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError>;
    fn get_identity_key(
        &self,
        address: ProtocolAddress,
    ) -> Result<Option<PublicKey>, SignalProtocolError>;
    // TODO: Use AsType for stronger types on these raw integers.
    fn save_identity_key(
        &self,
        address: ProtocolAddress,
        public_key: PublicKey,
    ) -> Result</*IdentityChange*/ u8, SignalProtocolError>;
    fn is_trusted_identity(
        &self,
        address: ProtocolAddress,
        public_key: PublicKey,
        direction: /*Direction*/ u32,
    ) -> Result<bool, SignalProtocolError>;
}

// TODO: This alias is because of the ffi_arg_type macro expecting all bridging structs to use a
// particular naming scheme; eventually we should be able to remove it.
pub type FfiIdentityKeyStoreStruct = FfiBridgeIdentityKeyStoreStruct;

#[derive(Debug)]
#[repr(C)]
pub enum FfiDirection {
    Sending = 0,
    Receiving = 1,
}

#[async_trait(?Send)]
impl<T: BridgeIdentityKeyStore> IdentityKeyStore for BridgedStore<T> {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let priv_key = self.0.get_local_identity_private_key()?;
        let pub_key = priv_key.public_key()?;
        Ok(IdentityKeyPair::new(IdentityKey::new(pub_key), priv_key))
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        self.0.get_local_registration_id()
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let raw_result = self
            .0
            .save_identity_key(address.clone(), *identity.public_key())?;
        IdentityChange::try_from(isize::from(raw_result)).map_err(|_| {
            SignalProtocolError::FfiBindingError(format!(
                "invalid result for save_identity: {raw_result}"
            ))
        })
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        let direction = match direction {
            Direction::Sending => FfiDirection::Sending,
            Direction::Receiving => FfiDirection::Receiving,
        };
        self.0
            .is_trusted_identity(address.clone(), *identity.public_key(), direction as u32)
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        Ok(self
            .0
            .get_identity_key(address.clone())?
            .map(IdentityKey::new))
    }
}

/// A bridge-friendly version of [`PreKeyStore`].
#[bridge_callbacks(jni = false, node = false)]
pub trait BridgePreKeyStore {
    fn load_pre_key(&self, id: u32) -> Result<Option<PreKeyRecord>, SignalProtocolError>;
    fn store_pre_key(&self, id: u32, record: PreKeyRecord) -> Result<(), SignalProtocolError>;
    fn remove_pre_key(&self, id: u32) -> Result<(), SignalProtocolError>;
}

// TODO: This alias is because of the ffi_arg_type macro expecting all bridging structs to use a
// particular naming scheme; eventually we should be able to remove it.
pub type FfiPreKeyStoreStruct = FfiBridgePreKeyStoreStruct;

#[async_trait(?Send)]
impl<T: BridgePreKeyStore> PreKeyStore for BridgedStore<T> {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        self.0
            .load_pre_key(prekey_id.into())?
            .ok_or(SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0.store_pre_key(prekey_id.into(), record.clone())
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        self.0.remove_pre_key(prekey_id.into())
    }
}

/// A bridge-friendly version of [`SignedPreKeyStore`].
#[bridge_callbacks(jni = false, node = false)]
pub trait BridgeSignedPreKeyStore {
    fn load_signed_pre_key(
        &self,
        id: u32,
    ) -> Result<Option<SignedPreKeyRecord>, SignalProtocolError>;
    fn store_signed_pre_key(
        &self,
        id: u32,
        record: SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError>;
}

// TODO: This alias is because of the ffi_arg_type macro expecting all bridging structs to use a
// particular naming scheme; eventually we should be able to remove it.
pub type FfiSignedPreKeyStoreStruct = FfiBridgeSignedPreKeyStoreStruct;

#[async_trait(?Send)]
impl<T: BridgeSignedPreKeyStore> SignedPreKeyStore for BridgedStore<T> {
    async fn get_signed_pre_key(
        &self,
        prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        self.0
            .load_signed_pre_key(prekey_id.into())?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)
    }

    async fn save_signed_pre_key(
        &mut self,
        prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0
            .store_signed_pre_key(prekey_id.into(), record.clone())
    }
}

/// A bridge-friendly version of [`KyberPreKeyStore`].
#[bridge_callbacks(jni = false, node = false)]
pub trait BridgeKyberPreKeyStore {
    fn load_kyber_pre_key(&self, id: u32)
    -> Result<Option<KyberPreKeyRecord>, SignalProtocolError>;
    fn store_kyber_pre_key(
        &self,
        id: u32,
        record: KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError>;
    fn mark_kyber_pre_key_used(
        &self,
        id: u32,
        ec_prekey_id: u32,
        base_key: PublicKey,
    ) -> Result<(), SignalProtocolError>;
}

// TODO: This alias is because of the ffi_arg_type macro expecting all bridging structs to use a
// particular naming scheme; eventually we should be able to remove it.
pub type FfiKyberPreKeyStoreStruct = FfiBridgeKyberPreKeyStoreStruct;

#[async_trait(?Send)]
impl<T: BridgeKyberPreKeyStore> KyberPreKeyStore for BridgedStore<T> {
    async fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        BridgeKyberPreKeyStore::load_kyber_pre_key(&self.0, id.into())?
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        BridgeKyberPreKeyStore::store_kyber_pre_key(&self.0, id.into(), record.clone())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        BridgeKyberPreKeyStore::mark_kyber_pre_key_used(
            &self.0,
            id.into(),
            ec_prekey_id.into(),
            *base_key,
        )
    }
}

/// A bridge-friendly version of [`SessionStore`].
#[bridge_callbacks(jni = false, node = false)]
pub trait BridgeSessionStore {
    fn load_session(
        &self,
        address: ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError>;
    fn store_session(
        &self,
        address: ProtocolAddress,
        record: SessionRecord,
    ) -> Result<(), SignalProtocolError>;
}

// TODO: This alias is because of the ffi_arg_type macro expecting all bridging structs to use a
// particular naming scheme; eventually we should be able to remove it.
pub type FfiSessionStoreStruct = FfiBridgeSessionStoreStruct;

#[async_trait(?Send)]
impl<T: BridgeSessionStore> SessionStore for BridgedStore<T> {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        self.0.load_session(address.clone())
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0.store_session(address.clone(), record.clone())
    }
}

/// A bridge-friendly version of [`SenderKeyStore`].
#[bridge_callbacks(jni = false, node = false)]
pub trait BridgeSenderKeyStore {
    fn load_sender_key(
        &self,
        sender: ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError>;
    fn store_sender_key(
        &self,
        sender: ProtocolAddress,
        distribution_id: Uuid,
        record: SenderKeyRecord,
    ) -> Result<(), SignalProtocolError>;
}

// TODO: This alias is because of the ffi_arg_type macro expecting all bridging structs to use a
// particular naming scheme; eventually we should be able to remove it.
pub type FfiSenderKeyStoreStruct = FfiBridgeSenderKeyStoreStruct;

#[async_trait(?Send)]
impl<T: BridgeSenderKeyStore> SenderKeyStore for BridgedStore<T> {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0
            .store_sender_key(sender.clone(), distribution_id, record.clone())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        self.0.load_sender_key(sender.clone(), distribution_id)
    }
}
