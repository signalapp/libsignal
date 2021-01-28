//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]

use async_trait::async_trait;
use libc::{c_char, c_int, c_uchar, c_uint, c_ulonglong, size_t};
use libsignal_bridge::ffi::*;
use libsignal_protocol_rust::*;
use static_assertions::const_assert_eq;
use std::convert::TryFrom;
use std::ffi::{c_void, CString};
use std::fmt;

pub mod logging;
mod util;

use crate::util::*;

#[no_mangle]
pub unsafe extern "C" fn signal_print_ptr(p: *const std::ffi::c_void) {
    println!("In rust thats {:?}", p);
}

#[no_mangle]
pub unsafe extern "C" fn signal_free_string(buf: *const c_char) {
    if buf.is_null() {
        return;
    }
    CString::from_raw(buf as _);
}

#[no_mangle]
pub unsafe extern "C" fn signal_free_buffer(buf: *const c_uchar, buf_len: size_t) {
    if buf.is_null() {
        return;
    }
    Box::from_raw(std::slice::from_raw_parts_mut(buf as *mut c_uchar, buf_len));
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_message(
    err: *const SignalFfiError,
    out: *mut *const c_char,
) -> *mut SignalFfiError {
    let result = (|| {
        if err.is_null() {
            return Err(SignalFfiError::NullPointer);
        }
        let msg = format!("{}", *err);
        write_cstr_to(out, Ok(msg))
    })();

    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => Box::into_raw(Box::new(e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_type(err: *const SignalFfiError) -> u32 {
    match err.as_ref() {
        Some(err) => {
            let code: SignalErrorCode = err.into();
            code as u32
        }
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_free(err: *mut SignalFfiError) {
    if !err.is_null() {
        let _boxed_err = Box::from_raw(err);
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_hkdf_derive(
    output: *mut c_uchar,
    output_length: size_t,
    version: c_int,
    input_key_material: *const c_uchar,
    input_key_material_len: size_t,
    salt: *const c_uchar,
    salt_len: size_t,
    info: *const c_uchar,
    info_len: size_t,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        if input_key_material.is_null() {
            return Err(SignalFfiError::NullPointer);
        }

        let output_buffer = as_slice_mut(output, output_length)?;
        let input_key_material = as_slice(input_key_material, input_key_material_len)?;
        let salt = as_slice(salt, salt_len)?;
        let info = as_slice(info, info_len)?;

        let hkdf = HKDF::new(version as u32)?;
        let kdf_output =
            hkdf.derive_salted_secrets(input_key_material, salt, info, output_length)?;

        output_buffer.copy_from_slice(&kdf_output);

        Ok(())
    })
}

ffi_fn_get_uint32!(signal_address_get_device_id(ProtocolAddress) using
                   |obj: &ProtocolAddress| { Ok(obj.device_id()) });

ffi_fn_clone!(signal_address_clone clones ProtocolAddress);

ffi_fn_clone!(signal_publickey_clone clones PublicKey);

ffi_fn_clone!(signal_privatekey_clone clones PrivateKey);

#[no_mangle]
pub unsafe extern "C" fn signal_identitykeypair_deserialize(
    private_key: *mut *mut PrivateKey,
    public_key: *mut *mut PublicKey,
    input: *const c_uchar,
    input_len: size_t,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let input = as_slice(input, input_len)?;
        let identity_key_pair = IdentityKeyPair::try_from(input)?;
        box_object::<PublicKey>(public_key, Ok(*identity_key_pair.public_key()))?;
        box_object::<PrivateKey>(private_key, Ok(*identity_key_pair.private_key()))
    })
}

ffi_fn_get_uint32!(signal_session_record_get_remote_registration_id(SessionRecord) using
                   SessionRecord::remote_registration_id);

#[no_mangle]
pub unsafe extern "C" fn signal_session_record_archive_current_state(
    session_record: *mut SessionRecord,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let session_record = native_handle_cast_mut::<SessionRecord>(session_record)?;
        session_record.archive_current_state()?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_session_record_has_current_state(
    result: *mut bool,
    session_record: *const SessionRecord,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        if result.is_null() {
            return Err(SignalFfiError::NullPointer);
        }
        let session_record = native_handle_cast::<SessionRecord>(session_record)?;
        *result = session_record.has_current_session_state();
        Ok(())
    })
}

ffi_fn_clone!(signal_session_record_clone clones SessionRecord);

#[no_mangle]
pub unsafe extern "C" fn signal_fingerprint_new(
    obj: *mut *mut Fingerprint,
    iterations: c_uint,
    version: c_uint,
    local_identifier: *const c_uchar,
    local_identifier_len: size_t,
    local_key: *const PublicKey,
    remote_identifier: *const c_uchar,
    remote_identifier_len: size_t,
    remote_key: *const PublicKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let local_identifier = as_slice(local_identifier, local_identifier_len)?;
        let local_key = native_handle_cast::<PublicKey>(local_key)?;

        let remote_identifier = as_slice(remote_identifier, remote_identifier_len)?;
        let remote_key = native_handle_cast::<PublicKey>(remote_key)?;

        let fprint = Fingerprint::new(
            version,
            iterations,
            local_identifier,
            &IdentityKey::new(*local_key),
            remote_identifier,
            &IdentityKey::new(*remote_key),
        );

        box_object::<Fingerprint>(obj, fprint)
    })
}

ffi_fn_clone!(signal_fingerprint_clone clones Fingerprint);

ffi_fn_clone!(signal_message_clone clones SignalMessage);

ffi_fn_get_new_boxed_obj!(signal_message_get_sender_ratchet_key(PublicKey) from SignalMessage,
                          |p: &SignalMessage| Ok(*p.sender_ratchet_key()));

ffi_fn_get_uint32!(signal_message_get_message_version(SignalMessage) using
                   |msg: &SignalMessage| { Ok(msg.message_version() as u32) });

ffi_fn_get_uint32!(signal_message_get_counter(SignalMessage) using
                   |msg: &SignalMessage| { Ok(msg.counter()) });

ffi_fn_clone!(signal_pre_key_signal_message_clone clones PreKeySignalMessage);

ffi_fn_get_uint32!(signal_pre_key_signal_message_get_version(PreKeySignalMessage) using
                   |m: &PreKeySignalMessage| Ok(m.message_version() as u32));

ffi_fn_get_uint32!(signal_pre_key_signal_message_get_registration_id(PreKeySignalMessage) using
                   |m: &PreKeySignalMessage| Ok(m.registration_id()));

ffi_fn_get_optional_uint32!(signal_pre_key_signal_message_get_pre_key_id(PreKeySignalMessage) using
                            |m: &PreKeySignalMessage| Ok(m.pre_key_id()));

ffi_fn_get_uint32!(signal_pre_key_signal_message_get_signed_pre_key_id(PreKeySignalMessage) using
                   |m: &PreKeySignalMessage| Ok(m.signed_pre_key_id()));

ffi_fn_get_new_boxed_obj!(signal_pre_key_signal_message_get_base_key(PublicKey) from PreKeySignalMessage,
                          |p: &PreKeySignalMessage| Ok(*p.base_key()));

ffi_fn_get_new_boxed_obj!(signal_pre_key_signal_message_get_identity_key(PublicKey) from PreKeySignalMessage,
                          |p: &PreKeySignalMessage| Ok(*p.identity_key().public_key()));

ffi_fn_get_new_boxed_obj!(signal_pre_key_signal_message_get_signal_message(SignalMessage) from PreKeySignalMessage,
                          |p: &PreKeySignalMessage| Ok(p.message().clone()));

ffi_fn_clone!(signal_sender_key_message_clone clones SenderKeyMessage);

ffi_fn_get_uint32!(signal_sender_key_message_get_key_id(SenderKeyMessage) using
                   |m: &SenderKeyMessage| Ok(m.key_id()));

ffi_fn_get_uint32!(signal_sender_key_message_get_iteration(SenderKeyMessage) using
                   |m: &SenderKeyMessage| Ok(m.iteration()));

ffi_fn_clone!(signal_sender_key_distribution_message_clone clones SenderKeyDistributionMessage);

ffi_fn_get_uint32!(signal_sender_key_distribution_message_get_id(SenderKeyDistributionMessage) using
                   |m: &SenderKeyDistributionMessage| m.id());

ffi_fn_get_uint32!(signal_sender_key_distribution_message_get_iteration(SenderKeyDistributionMessage) using
                   |m: &SenderKeyDistributionMessage| m.iteration());

ffi_fn_get_new_boxed_obj!(signal_sender_key_distribution_message_get_signature_key(PublicKey) from SenderKeyDistributionMessage,
                          |m: &SenderKeyDistributionMessage| Ok(*m.signing_key()?));

#[no_mangle]
pub unsafe extern "C" fn signal_pre_key_bundle_new(
    obj: *mut *mut PreKeyBundle,
    registration_id: c_uint,
    device_id: c_uint,
    prekey_id: *const c_uint,
    prekey: *const PublicKey,
    signed_prekey_id: c_uint,
    signed_prekey: *const PublicKey,
    signed_prekey_signature: *const c_uchar,
    signed_prekey_signature_len: size_t,
    identity_key: *const PublicKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let signed_prekey = native_handle_cast::<PublicKey>(signed_prekey)?;
        let signed_prekey_signature =
            as_slice(signed_prekey_signature, signed_prekey_signature_len)?;

        let identity_key = IdentityKey::new(*(identity_key as *const PublicKey));

        let prekey = native_handle_cast_optional::<PublicKey>(prekey)?.copied();
        let prekey_id = get_optional_uint32(prekey_id);

        let prekey = match (prekey, prekey_id) {
            (None, None) => None,
            (Some(k), Some(id)) => Some((id, k)),
            _ => {
                return Err(SignalFfiError::Signal(
                    SignalProtocolError::InvalidArgument(
                        "Must supply both or neither of prekey and prekey_id".to_owned(),
                    ),
                ))
            }
        };

        let bundle = PreKeyBundle::new(
            registration_id,
            device_id,
            prekey,
            signed_prekey_id,
            *signed_prekey,
            signed_prekey_signature.to_vec(),
            identity_key,
        );

        box_object::<PreKeyBundle>(obj, bundle)
    })
}

ffi_fn_clone!(signal_pre_key_bundle_clone clones PreKeyBundle);

ffi_fn_get_uint32!(signal_pre_key_bundle_get_registration_id(PreKeyBundle) using
                   |m: &PreKeyBundle| m.registration_id());

ffi_fn_get_uint32!(signal_pre_key_bundle_get_device_id(PreKeyBundle) using
                   |m: &PreKeyBundle| m.device_id());

ffi_fn_get_uint32!(signal_pre_key_bundle_get_signed_pre_key_id(PreKeyBundle) using
                   |m: &PreKeyBundle| m.signed_pre_key_id());

ffi_fn_get_optional_uint32!(signal_pre_key_bundle_get_pre_key_id(PreKeyBundle) using
                            |m: &PreKeyBundle| m.pre_key_id());

ffi_fn_get_new_boxed_optional_obj!(signal_pre_key_bundle_get_pre_key_public(PublicKey) from PreKeyBundle,
                                   |p: &PreKeyBundle| p.pre_key_public());

ffi_fn_get_new_boxed_obj!(signal_pre_key_bundle_get_signed_pre_key_public(PublicKey) from PreKeyBundle,
                          |p: &PreKeyBundle| Ok(p.signed_pre_key_public()?));

ffi_fn_get_new_boxed_obj!(signal_pre_key_bundle_get_identity_key(PublicKey) from PreKeyBundle,
                          |p: &PreKeyBundle| Ok(*p.identity_key()?.public_key()));

/* SignedPreKeyRecord */

ffi_fn_get_uint32!(signal_signed_pre_key_record_get_id(SignedPreKeyRecord) using
                   |m: &SignedPreKeyRecord| m.id());

ffi_fn_get_uint64!(signal_signed_pre_key_record_get_timestamp(SignedPreKeyRecord) using
                   |m: &SignedPreKeyRecord| m.timestamp());

ffi_fn_get_new_boxed_obj!(signal_signed_pre_key_record_get_public_key(PublicKey) from SignedPreKeyRecord,
                          |p: &SignedPreKeyRecord| p.public_key());

ffi_fn_get_new_boxed_obj!(signal_signed_pre_key_record_get_private_key(PrivateKey) from SignedPreKeyRecord,
                          |p: &SignedPreKeyRecord| p.private_key());

ffi_fn_clone!(signal_signed_pre_key_record_clone clones SignedPreKeyRecord);

/* PreKeyRecord */

ffi_fn_get_uint32!(signal_pre_key_record_get_id(PreKeyRecord) using
                   |m: &PreKeyRecord| m.id());

ffi_fn_get_new_boxed_obj!(signal_pre_key_record_get_public_key(PublicKey) from PreKeyRecord,
                          |p: &PreKeyRecord| p.public_key());

ffi_fn_get_new_boxed_obj!(signal_pre_key_record_get_private_key(PrivateKey) from PreKeyRecord,
                          |p: &PreKeyRecord| p.private_key());

ffi_fn_clone!(signal_pre_key_record_clone clones PreKeyRecord);

/* SenderKeyName */
ffi_fn_clone!(signal_sender_key_name_clone clones SenderKeyName);

ffi_fn_get_uint32!(signal_sender_key_name_get_sender_device_id(SenderKeyName) using
                   |m: &SenderKeyName| Ok(m.sender()?.device_id()));

ffi_fn_clone!(signal_sender_key_record_clone clones SenderKeyRecord);

type GetIdentityKeyPair =
    extern "C" fn(store_ctx: *mut c_void, keyp: *mut *mut PrivateKey, ctx: *mut c_void) -> c_int;
type GetLocalRegistrationId =
    extern "C" fn(store_ctx: *mut c_void, idp: *mut u32, ctx: *mut c_void) -> c_int;
type GetIdentityKey = extern "C" fn(
    store_ctx: *mut c_void,
    public_keyp: *mut *mut PublicKey,
    address: *const ProtocolAddress,
    ctx: *mut c_void,
) -> c_int;
type SaveIdentityKey = extern "C" fn(
    store_ctx: *mut c_void,
    address: *const ProtocolAddress,
    public_key: *const PublicKey,
    ctx: *mut c_void,
) -> c_int;
type IsTrustedIdentity = extern "C" fn(
    store_ctx: *mut c_void,
    address: *const ProtocolAddress,
    public_key: *const PublicKey,
    direction: c_uint,
    ctx: *mut c_void,
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

pub struct FfiIdentityKeyStore {
    store: FfiIdentityKeyStoreStruct,
}

impl FfiIdentityKeyStore {
    fn new(store: *const FfiIdentityKeyStoreStruct) -> Result<Self, SignalFfiError> {
        Ok(Self {
            store: *unsafe { store.as_ref() }.ok_or(SignalFfiError::NullPointer)?,
        })
    }
}

#[derive(Debug)]
struct CallbackError {
    value: std::num::NonZeroI32,
}

impl CallbackError {
    fn check(value: i32) -> Option<Self> {
        let value = std::num::NonZeroI32::try_from(value).ok()?;
        Some(Self { value })
    }
}

impl fmt::Display for CallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error code {}", self.value)
    }
}

impl std::error::Error for CallbackError {}

#[async_trait(?Send)]
impl IdentityKeyStore for FfiIdentityKeyStore {
    async fn get_identity_key_pair(
        &self,
        ctx: Context,
    ) -> Result<IdentityKeyPair, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut key = std::ptr::null_mut();
        let result = (self.store.get_identity_key_pair)(self.store.ctx, &mut key, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "get_identity_key_pair",
                Box::new(error),
            ));
        }

        if key.is_null() {
            return Err(SignalProtocolError::InternalError("No identity key pair"));
        }

        let priv_key = unsafe { Box::from_raw(key) };
        let pub_key = priv_key.public_key()?;

        Ok(IdentityKeyPair::new(IdentityKey::new(pub_key), *priv_key))
    }

    async fn get_local_registration_id(&self, ctx: Context) -> Result<u32, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut id = 0;
        let result = (self.store.get_local_registration_id)(self.store.ctx, &mut id, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "get_local_registration_id",
                Box::new(error),
            ));
        }

        Ok(id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result =
            (self.store.save_identity)(self.store.ctx, &*address, &*identity.public_key(), ctx);

        match result {
            0 => Ok(false),
            1 => Ok(true),
            r => Err(SignalProtocolError::ApplicationCallbackError(
                "save_identity",
                Box::new(CallbackError::check(r).unwrap()),
            )),
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
        ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let direction = match direction {
            Direction::Sending => FfiDirection::Sending,
            Direction::Receiving => FfiDirection::Receiving,
        };
        let result = (self.store.is_trusted_identity)(
            self.store.ctx,
            &*address,
            &*identity.public_key(),
            direction as u32,
            ctx,
        );

        match result {
            0 => Ok(false),
            1 => Ok(true),
            r => Err(SignalProtocolError::ApplicationCallbackError(
                "is_trusted_identity",
                Box::new(CallbackError::check(r).unwrap()),
            )),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut key = std::ptr::null_mut();
        let result = (self.store.get_identity)(self.store.ctx, &mut key, &*address, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "get_identity",
                Box::new(error),
            ));
        }

        if key.is_null() {
            return Ok(None);
        }

        let pk = unsafe { Box::from_raw(key) };

        Ok(Some(IdentityKey::new(*pk)))
    }
}

type LoadPreKey = extern "C" fn(
    store_ctx: *mut c_void,
    recordp: *mut *mut PreKeyRecord,
    id: u32,
    ctx: *mut c_void,
) -> c_int;
type StorePreKey = extern "C" fn(
    store_ctx: *mut c_void,
    id: u32,
    record: *const PreKeyRecord,
    ctx: *mut c_void,
) -> c_int;
type RemovePreKey = extern "C" fn(store_ctx: *mut c_void, id: u32, ctx: *mut c_void) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiPreKeyStoreStruct {
    ctx: *mut c_void,
    load_pre_key: LoadPreKey,
    store_pre_key: StorePreKey,
    remove_pre_key: RemovePreKey,
}

pub struct FfiPreKeyStore {
    store: FfiPreKeyStoreStruct,
}

impl FfiPreKeyStore {
    fn new(store: *const FfiPreKeyStoreStruct) -> Result<Self, SignalFfiError> {
        Ok(Self {
            store: *unsafe { store.as_ref() }.ok_or(SignalFfiError::NullPointer)?,
        })
    }
}

#[async_trait(?Send)]
impl PreKeyStore for FfiPreKeyStore {
    async fn get_pre_key(
        &self,
        prekey_id: u32,
        ctx: Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut record = std::ptr::null_mut();
        let result = (self.store.load_pre_key)(self.store.ctx, &mut record, prekey_id, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "load_pre_key",
                Box::new(error),
            ));
        }

        if record.is_null() {
            return Err(SignalProtocolError::InvalidPreKeyId);
        }

        let record = unsafe { Box::from_raw(record) };
        Ok(*record)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &PreKeyRecord,
        ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result = (self.store.store_pre_key)(self.store.ctx, prekey_id, &*record, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "store_pre_key",
                Box::new(error),
            ));
        }

        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: u32,
        ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result = (self.store.remove_pre_key)(self.store.ctx, prekey_id, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "remove_pre_key",
                Box::new(error),
            ));
        }

        Ok(())
    }
}

type LoadSignedPreKey = extern "C" fn(
    store_ctx: *mut c_void,
    recordp: *mut *mut SignedPreKeyRecord,
    id: u32,
    ctx: *mut c_void,
) -> c_int;
type StoreSignedPreKey = extern "C" fn(
    store_ctx: *mut c_void,
    id: u32,
    record: *const SignedPreKeyRecord,
    ctx: *mut c_void,
) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiSignedPreKeyStoreStruct {
    ctx: *mut c_void,
    load_signed_pre_key: LoadSignedPreKey,
    store_signed_pre_key: StoreSignedPreKey,
}

pub struct FfiSignedPreKeyStore {
    store: FfiSignedPreKeyStoreStruct,
}

impl FfiSignedPreKeyStore {
    fn new(store: *const FfiSignedPreKeyStoreStruct) -> Result<Self, SignalFfiError> {
        Ok(Self {
            store: *unsafe { store.as_ref() }.ok_or(SignalFfiError::NullPointer)?,
        })
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for FfiSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        prekey_id: u32,
        ctx: Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut record = std::ptr::null_mut();
        let result = (self.store.load_signed_pre_key)(self.store.ctx, &mut record, prekey_id, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "load_signed_pre_key",
                Box::new(error),
            ));
        }

        if record.is_null() {
            return Err(SignalProtocolError::InvalidSignedPreKeyId);
        }

        let record = unsafe { Box::from_raw(record) };

        Ok(*record)
    }

    async fn save_signed_pre_key(
        &mut self,
        prekey_id: u32,
        record: &SignedPreKeyRecord,
        ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result = (self.store.store_signed_pre_key)(self.store.ctx, prekey_id, &*record, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "store_signed_pre_key",
                Box::new(error),
            ));
        }

        Ok(())
    }
}

type LoadSession = extern "C" fn(
    store_ctx: *mut c_void,
    recordp: *mut *mut SessionRecord,
    address: *const ProtocolAddress,
    ctx: *mut c_void,
) -> c_int;
type StoreSession = extern "C" fn(
    store_ctx: *mut c_void,
    address: *const ProtocolAddress,
    record: *const SessionRecord,
    ctx: *mut c_void,
) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiSessionStoreStruct {
    ctx: *mut c_void,
    load_session: LoadSession,
    store_session: StoreSession,
}

pub struct FfiSessionStore {
    store: FfiSessionStoreStruct,
}

impl FfiSessionStore {
    fn new(store: *const FfiSessionStoreStruct) -> Result<Self, SignalFfiError> {
        Ok(Self {
            store: *unsafe { store.as_ref() }.ok_or(SignalFfiError::NullPointer)?,
        })
    }
}

#[async_trait(?Send)]
impl SessionStore for FfiSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut record = std::ptr::null_mut();
        let result = (self.store.load_session)(self.store.ctx, &mut record, &*address, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "load_session",
                Box::new(error),
            ));
        }

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
        ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result = (self.store.store_session)(self.store.ctx, &*address, &*record, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "store_session",
                Box::new(error),
            ));
        }

        Ok(())
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_process_prekey_bundle(
    bundle: *mut PreKeyBundle,
    protocol_address: *const ProtocolAddress,
    session_store: *const FfiSessionStoreStruct,
    identity_key_store: *const FfiIdentityKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let bundle = native_handle_cast::<PreKeyBundle>(bundle)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;

        let mut identity_key_store = FfiIdentityKeyStore::new(identity_key_store)?;
        let mut session_store = FfiSessionStore::new(session_store)?;

        let mut csprng = rand::rngs::OsRng;
        expect_ready(process_prekey_bundle(
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            bundle,
            &mut csprng,
            Some(ctx),
        ))?;

        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_encrypt_message(
    msg: *mut *mut CiphertextMessage,
    ptext: *const c_uchar,
    ptext_len: size_t,
    protocol_address: *const ProtocolAddress,
    session_store: *const FfiSessionStoreStruct,
    identity_key_store: *const FfiIdentityKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let ptext = as_slice(ptext, ptext_len)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;

        let mut identity_key_store = FfiIdentityKeyStore::new(identity_key_store)?;
        let mut session_store = FfiSessionStore::new(session_store)?;

        let ctext = expect_ready(message_encrypt(
            &ptext,
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            Some(ctx),
        ));

        box_object(msg, ctext)
    })
}

#[derive(Debug)]
#[repr(C)]
pub enum FfiCiphertextMessageType {
    Whisper = 2,
    PreKey = 3,
    SenderKey = 4,
    SenderKeyDistribution = 5,
}

const_assert_eq!(
    FfiCiphertextMessageType::Whisper as u8,
    CiphertextMessageType::Whisper as u8
);
const_assert_eq!(
    FfiCiphertextMessageType::PreKey as u8,
    CiphertextMessageType::PreKey as u8
);
const_assert_eq!(
    FfiCiphertextMessageType::SenderKey as u8,
    CiphertextMessageType::SenderKey as u8
);
const_assert_eq!(
    FfiCiphertextMessageType::SenderKeyDistribution as u8,
    CiphertextMessageType::SenderKeyDistribution as u8
);

#[no_mangle]
pub unsafe extern "C" fn signal_ciphertext_message_type(
    typ: *mut u8,
    msg: *const CiphertextMessage,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let msg = native_handle_cast::<CiphertextMessage>(msg)?;
        *typ = msg.message_type() as u8;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_ciphertext_message_serialize(
    result: *mut *const c_uchar,
    result_len: *mut size_t,
    msg: *const CiphertextMessage,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let msg = native_handle_cast::<CiphertextMessage>(msg)?;
        let bits = msg.serialize();
        write_bytearray_to(result, result_len, bits)
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_decrypt_message(
    result: *mut *const c_uchar,
    result_len: *mut size_t,
    message: *const SignalMessage,
    protocol_address: *const ProtocolAddress,
    session_store: *const FfiSessionStoreStruct,
    identity_key_store: *const FfiIdentityKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let message = native_handle_cast::<SignalMessage>(message)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;

        let mut identity_key_store = FfiIdentityKeyStore::new(identity_key_store)?;
        let mut session_store = FfiSessionStore::new(session_store)?;

        let mut csprng = rand::rngs::OsRng;
        let ptext = expect_ready(message_decrypt_signal(
            &message,
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            &mut csprng,
            Some(ctx),
        ))?;
        write_bytearray_to(result, result_len, ptext)
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_decrypt_pre_key_message(
    result: *mut *const c_uchar,
    result_len: *mut size_t,
    message: *const PreKeySignalMessage,
    protocol_address: *const ProtocolAddress,
    session_store: *const FfiSessionStoreStruct,
    identity_key_store: *const FfiIdentityKeyStoreStruct,
    prekey_store: *const FfiPreKeyStoreStruct,
    signed_prekey_store: *const FfiSignedPreKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let message = native_handle_cast::<PreKeySignalMessage>(message)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;
        let mut identity_key_store = FfiIdentityKeyStore::new(identity_key_store)?;
        let mut session_store = FfiSessionStore::new(session_store)?;
        let mut prekey_store = FfiPreKeyStore::new(prekey_store)?;
        let mut signed_prekey_store = FfiSignedPreKeyStore::new(signed_prekey_store)?;

        let mut csprng = rand::rngs::OsRng;
        let ptext = expect_ready(message_decrypt_prekey(
            &message,
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            &mut prekey_store,
            &mut signed_prekey_store,
            &mut csprng,
            Some(ctx),
        ))?;

        write_bytearray_to(result, result_len, ptext)
    })
}

type LoadSenderKey = extern "C" fn(
    store_ctx: *mut c_void,
    *mut *mut SenderKeyRecord,
    *const SenderKeyName,
    ctx: *mut c_void,
) -> c_int;
type StoreSenderKey = extern "C" fn(
    store_ctx: *mut c_void,
    *const SenderKeyName,
    *const SenderKeyRecord,
    ctx: *mut c_void,
) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiSenderKeyStoreStruct {
    ctx: *mut c_void,
    load_sender_key: LoadSenderKey,
    store_sender_key: StoreSenderKey,
}

pub struct FfiSenderKeyStore {
    store: FfiSenderKeyStoreStruct,
}

impl FfiSenderKeyStore {
    fn new(store: *const FfiSenderKeyStoreStruct) -> Result<Self, SignalFfiError> {
        Ok(Self {
            store: *unsafe { store.as_ref() }.ok_or(SignalFfiError::NullPointer)?,
        })
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for FfiSenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
        ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result =
            (self.store.store_sender_key)(self.store.ctx, &*sender_key_name, &*record, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "store_sender_key",
                Box::new(error),
            ));
        }

        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        ctx: Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut record = std::ptr::null_mut();
        let result =
            (self.store.load_sender_key)(self.store.ctx, &mut record, &*sender_key_name, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "load_sender_key",
                Box::new(error),
            ));
        }

        if record.is_null() {
            return Ok(None);
        }

        let record = unsafe { Box::from_raw(record) };

        Ok(Some(*record))
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_create_sender_key_distribution_message(
    obj: *mut *mut SenderKeyDistributionMessage,
    sender_key_name: *const SenderKeyName,
    store: *const FfiSenderKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        if sender_key_name.is_null() || store.is_null() {
            return Err(SignalFfiError::NullPointer);
        }
        let sender_key_name = native_handle_cast::<SenderKeyName>(sender_key_name)?;

        let mut sender_key_store = FfiSenderKeyStore::new(store)?;
        let mut csprng = rand::rngs::OsRng;

        let skdm = expect_ready(create_sender_key_distribution_message(
            &sender_key_name,
            &mut sender_key_store,
            &mut csprng,
            Some(ctx),
        ));

        box_object::<SenderKeyDistributionMessage>(obj, skdm)
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_process_sender_key_distribution_message(
    sender_key_name: *const SenderKeyName,
    sender_key_distribution_message: *const SenderKeyDistributionMessage,
    store: *const FfiSenderKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let sender_key_name = native_handle_cast::<SenderKeyName>(sender_key_name)?;
        let sender_key_distribution_message =
            native_handle_cast::<SenderKeyDistributionMessage>(sender_key_distribution_message)?;
        let mut sender_key_store = FfiSenderKeyStore::new(store)?;

        expect_ready(process_sender_key_distribution_message(
            sender_key_name,
            sender_key_distribution_message,
            &mut sender_key_store,
            Some(ctx),
        ))?;

        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_group_encrypt_message(
    out: *mut *const c_uchar,
    out_len: *mut size_t,
    sender_key_name: *const SenderKeyName,
    message: *const c_uchar,
    message_len: size_t,
    store: *const FfiSenderKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let sender_key_name = native_handle_cast::<SenderKeyName>(sender_key_name)?;
        let message = as_slice(message, message_len)?;
        let mut sender_key_store = FfiSenderKeyStore::new(store)?;
        let mut rng = rand::rngs::OsRng;
        let ctext = expect_ready(group_encrypt(
            &mut sender_key_store,
            &sender_key_name,
            &message,
            &mut rng,
            Some(ctx),
        ))?;
        write_bytearray_to(out, out_len, ctext)
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_group_decrypt_message(
    out: *mut *const c_uchar,
    out_len: *mut size_t,
    sender_key_name: *const SenderKeyName,
    message: *const c_uchar,
    message_len: size_t,
    store: *const FfiSenderKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let sender_key_name = native_handle_cast::<SenderKeyName>(sender_key_name)?;
        let message = as_slice(message, message_len)?;
        let mut sender_key_store = FfiSenderKeyStore::new(store)?;

        let ptext = expect_ready(group_decrypt(
            &message,
            &mut sender_key_store,
            &sender_key_name,
            Some(ctx),
        ))?;
        write_bytearray_to(out, out_len, ptext)
    })
}

// Server Certificate
ffi_fn_get_uint32!(signal_server_certificate_get_key_id(ServerCertificate) using ServerCertificate::key_id);

ffi_fn_get_new_boxed_obj!(signal_server_certificate_get_key(PublicKey) from ServerCertificate,
                          ServerCertificate::public_key);

// Sender Certificate
ffi_fn_get_uint64!(signal_sender_certificate_get_expiration(SenderCertificate) using SenderCertificate::expiration);
ffi_fn_get_uint32!(signal_sender_certificate_get_device_id(SenderCertificate) using SenderCertificate::sender_device_id);

ffi_fn_get_new_boxed_obj!(signal_sender_certificate_get_key(PublicKey) from SenderCertificate,
                          SenderCertificate::key);
ffi_fn_get_new_boxed_obj!(signal_sender_certificate_get_server_certificate(ServerCertificate) from SenderCertificate,
                          |s: &SenderCertificate| Ok(s.signer()?.clone()));

// UnidentifiedSenderMessageContent
#[no_mangle]
pub unsafe extern "C" fn signal_unidentified_sender_message_content_get_msg_type(
    out: *mut u8,
    obj: *const UnidentifiedSenderMessageContent,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let msg = native_handle_cast::<UnidentifiedSenderMessageContent>(obj)?;
        *out = msg.msg_type()? as u8;
        Ok(())
    })
}

ffi_fn_get_new_boxed_obj!(signal_unidentified_sender_message_content_get_sender_cert(SenderCertificate) from UnidentifiedSenderMessageContent,
                          |s: &UnidentifiedSenderMessageContent| Ok(s.sender()?.clone()));

#[no_mangle]
pub unsafe extern "C" fn signal_sealed_session_cipher_encrypt(
    out: *mut *const c_uchar,
    out_len: *mut size_t,
    destination: *const ProtocolAddress,
    sender_cert: *const SenderCertificate,
    ptext: *const c_uchar,
    ptext_len: size_t,
    session_store: *const FfiSessionStoreStruct,
    identity_key_store: *const FfiIdentityKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let destination = native_handle_cast::<ProtocolAddress>(destination)?;
        let sender_cert = native_handle_cast::<SenderCertificate>(sender_cert)?;
        let ptext = as_slice(ptext, ptext_len)?;

        let mut identity_store = FfiIdentityKeyStore::new(identity_key_store)?;
        let mut session_store = FfiSessionStore::new(session_store)?;

        let mut rng = rand::rngs::OsRng;

        let ctext = expect_ready(sealed_sender_encrypt(
            destination,
            sender_cert,
            &ptext,
            &mut session_store,
            &mut identity_store,
            Some(ctx),
            &mut rng,
        ))?;
        write_bytearray_to(out, out_len, ctext)
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_sealed_session_cipher_decrypt_to_usmc(
    out: *mut *mut UnidentifiedSenderMessageContent,
    ctext: *const c_uchar,
    ctext_len: size_t,
    identity_store: *const FfiIdentityKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let ctext = as_slice(ctext, ctext_len)?;
        let mut identity_store = FfiIdentityKeyStore::new(identity_store)?;

        let usmc = expect_ready(sealed_sender_decrypt_to_usmc(
            ctext,
            &mut identity_store,
            Some(ctx),
        ));

        box_object(out, usmc)
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_sealed_session_cipher_decrypt(
    out: *mut *const c_uchar,
    out_len: *mut size_t,
    sender_e164: *mut *const c_char,
    sender_uuid: *mut *const c_char,
    sender_device_id: *mut u32,
    ctext: *const c_uchar,
    ctext_len: size_t,
    trust_root: *const PublicKey,
    timestamp: u64,
    local_e164: *const c_char,
    local_uuid: *const c_char,
    local_device_id: c_uint,
    session_store: *const FfiSessionStoreStruct,
    identity_store: *const FfiIdentityKeyStoreStruct,
    prekey_store: *const FfiPreKeyStoreStruct,
    signed_prekey_store: *const FfiSignedPreKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let ctext = as_slice(ctext, ctext_len)?;
        let trust_root = native_handle_cast::<PublicKey>(trust_root)?;
        let mut identity_store = FfiIdentityKeyStore::new(identity_store)?;
        let mut session_store = FfiSessionStore::new(session_store)?;
        let mut prekey_store = FfiPreKeyStore::new(prekey_store)?;
        let mut signed_prekey_store = FfiSignedPreKeyStore::new(signed_prekey_store)?;

        let local_e164 = read_optional_c_string(local_e164)?;
        let local_uuid = read_optional_c_string(local_uuid)?;

        let decrypted = expect_ready(sealed_sender_decrypt(
            &ctext,
            trust_root,
            timestamp,
            local_e164,
            local_uuid,
            local_device_id,
            &mut identity_store,
            &mut session_store,
            &mut prekey_store,
            &mut signed_prekey_store,
            Some(ctx),
        ))?;

        write_optional_cstr_to(sender_e164, Ok(decrypted.sender_e164))?;
        write_optional_cstr_to(sender_uuid, Ok(decrypted.sender_uuid))?;
        write_uint32_to(sender_device_id, Ok(decrypted.device_id))?;
        write_bytearray_to(out, out_len, decrypted.message)
    })
}
