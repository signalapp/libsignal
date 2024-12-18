//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ffi::{c_int, c_uint, c_void};

use async_trait::async_trait;
use uuid::Uuid;

use super::*;

type GetIdentityKeyPair =
    extern "C" fn(store_ctx: *mut c_void, keyp: *mut MutPointer<PrivateKey>) -> c_int;
type GetLocalRegistrationId = extern "C" fn(store_ctx: *mut c_void, idp: *mut u32) -> c_int;
type GetIdentityKey = extern "C" fn(
    store_ctx: *mut c_void,
    public_keyp: *mut MutPointer<PublicKey>,
    address: ConstPointer<ProtocolAddress>,
) -> c_int;
type SaveIdentityKey = extern "C" fn(
    store_ctx: *mut c_void,
    address: ConstPointer<ProtocolAddress>,
    public_key: ConstPointer<PublicKey>,
) -> c_int;
type IsTrustedIdentity = extern "C" fn(
    store_ctx: *mut c_void,
    address: ConstPointer<ProtocolAddress>,
    public_key: ConstPointer<PublicKey>,
    direction: c_uint,
) -> c_int;

#[derive(Debug)]
#[repr(C)]
pub enum FfiDirection {
    Sending = 0,
    Receiving = 1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiIdentityKeyStoreStruct {
    ctx: *mut c_void,
    get_identity_key_pair: GetIdentityKeyPair,
    get_local_registration_id: GetLocalRegistrationId,
    save_identity: SaveIdentityKey,
    get_identity: GetIdentityKey,
    is_trusted_identity: IsTrustedIdentity,
}

#[async_trait(?Send)]
impl IdentityKeyStore for &FfiIdentityKeyStoreStruct {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let mut key = MutPointer::null();
        let result = (self.get_identity_key_pair)(self.ctx, &mut key);

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "get_identity_key_pair",
        ))?;

        let key = key.into_inner();
        if key.is_null() {
            return Err(SignalProtocolError::InvalidState(
                "get_identity_key_pair",
                "no local identity key".to_string(),
            ));
        }

        let priv_key = unsafe { Box::from_raw(key) };
        let pub_key = priv_key.public_key()?;

        Ok(IdentityKeyPair::new(IdentityKey::new(pub_key), *priv_key))
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        let mut id = 0;
        let result = (self.get_local_registration_id)(self.ctx, &mut id);

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "get_local_registration_id",
        ))?;

        Ok(id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalProtocolError> {
        let result = (self.save_identity)(self.ctx, address.into(), identity.public_key().into());

        match result {
            0 => Ok(false),
            1 => Ok(true),
            r => Err(SignalProtocolError::for_application_callback(
                "save_identity",
            )(
                CallbackError::check(r).expect_err("verified non-zero")
            )),
        }
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
        let result = (self.is_trusted_identity)(
            self.ctx,
            address.into(),
            identity.public_key().into(),
            direction as u32,
        );

        match result {
            0 => Ok(false),
            1 => Ok(true),
            r => Err(SignalProtocolError::for_application_callback(
                "is_trusted_identity",
            )(
                CallbackError::check(r).expect_err("verified non-zero")
            )),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let mut key = MutPointer::null();
        let result = (self.get_identity)(self.ctx, &mut key, address.into());

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "get_identity",
        ))?;

        let key = key.into_inner();
        if key.is_null() {
            return Ok(None);
        }

        let pk = unsafe { Box::from_raw(key) };

        Ok(Some(IdentityKey::new(*pk)))
    }
}

type LoadPreKey =
    extern "C" fn(store_ctx: *mut c_void, recordp: *mut MutPointer<PreKeyRecord>, id: u32) -> c_int;
type StorePreKey =
    extern "C" fn(store_ctx: *mut c_void, id: u32, record: ConstPointer<PreKeyRecord>) -> c_int;
type RemovePreKey = extern "C" fn(store_ctx: *mut c_void, id: u32) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiPreKeyStoreStruct {
    ctx: *mut c_void,
    load_pre_key: LoadPreKey,
    store_pre_key: StorePreKey,
    remove_pre_key: RemovePreKey,
}

#[async_trait(?Send)]
impl PreKeyStore for &FfiPreKeyStoreStruct {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let mut record = MutPointer::null();
        let result = (self.load_pre_key)(self.ctx, &mut record, prekey_id.into());

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "load_pre_key",
        ))?;

        let record = record.into_inner();
        if record.is_null() {
            return Err(SignalProtocolError::InvalidPreKeyId);
        }

        let record = unsafe { Box::from_raw(record) };
        Ok(*record)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let result = (self.store_pre_key)(self.ctx, prekey_id.into(), record.into());

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "store_pre_key",
        ))
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let result = (self.remove_pre_key)(self.ctx, prekey_id.into());

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "remove_pre_key",
        ))
    }
}

type LoadSignedPreKey = extern "C" fn(
    store_ctx: *mut c_void,
    recordp: *mut MutPointer<SignedPreKeyRecord>,
    id: u32,
) -> c_int;
type StoreSignedPreKey = extern "C" fn(
    store_ctx: *mut c_void,
    id: u32,
    record: ConstPointer<SignedPreKeyRecord>,
) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiSignedPreKeyStoreStruct {
    ctx: *mut c_void,
    load_signed_pre_key: LoadSignedPreKey,
    store_signed_pre_key: StoreSignedPreKey,
}

#[async_trait(?Send)]
impl SignedPreKeyStore for &FfiSignedPreKeyStoreStruct {
    async fn get_signed_pre_key(
        &self,
        prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let mut record = MutPointer::from(std::ptr::null_mut());
        let result = (self.load_signed_pre_key)(self.ctx, &mut record, prekey_id.into());

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "load_signed_pre_key",
        ))?;

        let record = record.into_inner();
        if record.is_null() {
            return Err(SignalProtocolError::InvalidSignedPreKeyId);
        }

        let record = unsafe { Box::from_raw(record) };

        Ok(*record)
    }

    async fn save_signed_pre_key(
        &mut self,
        prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let result = (self.store_signed_pre_key)(self.ctx, prekey_id.into(), record.into());

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "store_signed_pre_key",
        ))?;

        Ok(())
    }
}

type LoadKyberPreKey = extern "C" fn(
    store_ctx: *mut c_void,
    recordp: *mut MutPointer<KyberPreKeyRecord>,
    id: u32,
) -> c_int;
type StoreKyberPreKey = extern "C" fn(
    store_ctx: *mut c_void,
    id: u32,
    record: ConstPointer<KyberPreKeyRecord>,
) -> c_int;
type MarkKyberPreKeyUsed = extern "C" fn(store_ctx: *mut c_void, id: u32) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiKyberPreKeyStoreStruct {
    ctx: *mut c_void,
    load_kyber_pre_key: LoadKyberPreKey,
    store_kyber_pre_key: StoreKyberPreKey,
    mark_kyber_pre_key_used: MarkKyberPreKeyUsed,
}

#[async_trait(?Send)]
impl KyberPreKeyStore for &FfiKyberPreKeyStoreStruct {
    async fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let mut record = MutPointer::null();
        let result = (self.load_kyber_pre_key)(self.ctx, &mut record, id.into());

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "load_kyber_pre_key",
        ))?;

        let record = record.into_inner();
        if record.is_null() {
            return Err(SignalProtocolError::InvalidKyberPreKeyId);
        }

        let record = unsafe { Box::from_raw(record) };

        Ok(*record)
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let result = (self.store_kyber_pre_key)(self.ctx, id.into(), record.into());

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "store_kyber_pre_key",
        ))
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        let result = (self.mark_kyber_pre_key_used)(self.ctx, id.into());

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "mark_kyber_pre_key_used",
        ))
    }
}

type LoadSession = extern "C" fn(
    store_ctx: *mut c_void,
    recordp: *mut MutPointer<SessionRecord>,
    address: ConstPointer<ProtocolAddress>,
) -> c_int;
type StoreSession = extern "C" fn(
    store_ctx: *mut c_void,
    address: ConstPointer<ProtocolAddress>,
    record: ConstPointer<SessionRecord>,
) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiSessionStoreStruct {
    ctx: *mut c_void,
    load_session: LoadSession,
    store_session: StoreSession,
}

#[async_trait(?Send)]
impl SessionStore for &FfiSessionStoreStruct {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let mut record = MutPointer::null();
        let result = (self.load_session)(self.ctx, &mut record, address.into());

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "load_session",
        ))?;

        let record = record.into_inner();
        if record.is_null() {
            return Ok(None);
        }

        let record = unsafe { Box::from_raw(record) };

        Ok(Some(*record))
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let result = (self.store_session)(self.ctx, address.into(), record.into());

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "store_session",
        ))
    }
}

type LoadSenderKey = extern "C" fn(
    store_ctx: *mut c_void,
    *mut MutPointer<SenderKeyRecord>,
    ConstPointer<ProtocolAddress>,
    distribution_id: *const [u8; 16],
) -> c_int;
type StoreSenderKey = extern "C" fn(
    store_ctx: *mut c_void,
    ConstPointer<ProtocolAddress>,
    distribution_id: *const [u8; 16],
    ConstPointer<SenderKeyRecord>,
) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiSenderKeyStoreStruct {
    ctx: *mut c_void,
    load_sender_key: LoadSenderKey,
    store_sender_key: StoreSenderKey,
}

#[async_trait(?Send)]
impl SenderKeyStore for &FfiSenderKeyStoreStruct {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let result = (self.store_sender_key)(
            self.ctx,
            sender.into(),
            distribution_id.as_bytes(),
            record.into(),
        );

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "store_sender_key",
        ))
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let mut record = MutPointer::null();
        let result = (self.load_sender_key)(
            self.ctx,
            &mut record,
            sender.into(),
            distribution_id.as_bytes(),
        );

        CallbackError::check(result).map_err(SignalProtocolError::for_application_callback(
            "load_sender_key",
        ))?;

        let record = record.into_inner();
        if record.is_null() {
            return Ok(None);
        }

        let record = unsafe { Box::from_raw(record) };

        Ok(Some(*record))
    }
}
