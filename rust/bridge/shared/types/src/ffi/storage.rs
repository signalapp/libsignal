//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_bridge_macros::bridge_callbacks;

use super::*;
use crate::ffi;
use crate::protocol::storage::{
    FfiBridgeKyberPreKeyStoreStruct, FfiBridgePreKeyStoreStruct, FfiBridgeSenderKeyStoreStruct,
    FfiBridgeSessionStoreStruct, FfiBridgeSignedPreKeyStoreStruct,
};
use crate::support::{BridgedCallbacks, ResultLike, WithContext};

/// A bridge-friendly version of [`IdentityKeyStore`].
#[bridge_callbacks(jni = false, node = false)]
pub trait BridgeIdentityKeyStore {
    fn get_local_identity_key_pair(&self) -> Result<(PrivateKey, PublicKey), SignalProtocolError>;
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
impl<T: BridgeIdentityKeyStore> IdentityKeyStore for BridgedCallbacks<T> {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let (priv_key, pub_key) = self.0.get_local_identity_key_pair()?;
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

// TODO: These aliases are because of the ffi_arg_type macro expecting all bridging structs to use a
// particular naming scheme; eventually we should be able to remove them.
pub type FfiPreKeyStoreStruct = FfiBridgePreKeyStoreStruct;
pub type FfiSignedPreKeyStoreStruct = FfiBridgeSignedPreKeyStoreStruct;
pub type FfiKyberPreKeyStoreStruct = FfiBridgeKyberPreKeyStoreStruct;
pub type FfiSenderKeyStoreStruct = FfiBridgeSenderKeyStoreStruct;
pub type FfiSessionStoreStruct = FfiBridgeSessionStoreStruct;
