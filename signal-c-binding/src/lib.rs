#![allow(clippy::missing_safety_doc)]

use std::ffi::{CStr, c_char};
use std::ptr;
use std::time::{Duration, SystemTime};

use futures::executor::block_on;
use libsignal_core::{DeviceId, ProtocolAddress};
use libsignal_protocol::{
    CiphertextMessage, GenericSignedPreKey, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    InMemSignalProtocolStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyBundle, PreKeyId, PreKeyRecord, PreKeySignalMessage, PreKeyStore, SessionStore,
    SignalMessage, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
    Timestamp, UsePQRatchet, kem, message_decrypt_prekey, message_decrypt_signal, message_encrypt,
    process_prekey_bundle,
};
use rand::TryRngCore as _;
use rand::rngs::OsRng;

const KYBER_KEY_TYPE: kem::KeyType = kem::KeyType::Kyber1024;

// Mirror libsignal's OsRng usage so CryptoRng bounds are satisfied without
// introducing a different entropy source over the FFI boundary.
fn os_rng() -> impl rand::RngCore + rand::CryptoRng {
    OsRng.unwrap_err()
}

#[repr(C)]
pub struct SignalGoIdentityKeyPair {
    inner: IdentityKeyPair,
}

#[repr(C)]
pub struct SignalGoProtocolAddress {
    inner: ProtocolAddress,
}

#[repr(C)]
pub struct SignalGoProtocolStore {
    inner: InMemSignalProtocolStore,
}

#[repr(C)]
pub struct SignalGoCiphertextMessage {
    inner: CiphertextMessage,
}

#[repr(C)]
pub struct SignalGoSignalMessage {
    inner: SignalMessage,
}

#[repr(C)]
pub struct SignalGoPreKeySignalMessage {
    inner: PreKeySignalMessage,
}

#[repr(C)]
pub struct SignalGoPreKeyBundle {
    inner: PreKeyBundle,
}

fn system_time_from_millis(millis: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(millis)
}

fn timestamp_now() -> Timestamp {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time goes forwards");
    Timestamp::from_epoch_millis(now.as_millis() as u64)
}

fn error_code(err: SignalProtocolError) -> i32 {
    log::debug!("signal-c-binding error: {err:?}");
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_identity_keypair_generate() -> *mut SignalGoIdentityKeyPair {
    let mut rng = os_rng();
    let identity = IdentityKeyPair::generate(&mut rng);
    Box::into_raw(Box::new(SignalGoIdentityKeyPair { inner: identity }))
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_identity_keypair_free(ptr: *mut SignalGoIdentityKeyPair) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_identity_keypair_public_key(
    identity: *const SignalGoIdentityKeyPair,
    out_len: *mut usize,
) -> *mut u8 {
    if identity.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }
    let public_key = unsafe { (*identity).inner.public_key().serialize() };
    let len = public_key.len();
    let mut boxed = public_key;
    let ptr = boxed.as_mut_ptr();
    unsafe {
        *out_len = len;
    }
    std::mem::forget(boxed);
    ptr
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_identity_keypair_private_key(
    identity: *const SignalGoIdentityKeyPair,
    out_len: *mut usize,
) -> *mut u8 {
    if identity.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }
    let private_key = unsafe { (*identity).inner.private_key().serialize() };
    let len = private_key.len();
    let mut boxed = private_key;
    let ptr = boxed.as_mut_ptr();
    unsafe {
        *out_len = len;
    }
    std::mem::forget(boxed);
    ptr
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_protocol_address_new(
    name: *const c_char,
    device_id: u32,
) -> *mut SignalGoProtocolAddress {
    if name.is_null() {
        return ptr::null_mut();
    }

    let name = unsafe { CStr::from_ptr(name) };
    let name = match name.to_str() {
        Ok(value) => value.to_owned(),
        Err(_) => return ptr::null_mut(),
    };

    let device_id = match DeviceId::try_from(device_id) {
        Ok(id) => id,
        Err(_) => return ptr::null_mut(),
    };

    let address = ProtocolAddress::new(name, device_id);
    Box::into_raw(Box::new(SignalGoProtocolAddress { inner: address }))
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_protocol_address_free(ptr: *mut SignalGoProtocolAddress) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_protocol_store_new(
    identity: *const SignalGoIdentityKeyPair,
    registration_id: u32,
) -> *mut SignalGoProtocolStore {
    if identity.is_null() {
        return ptr::null_mut();
    }

    let identity = unsafe { (*identity).inner };

    let store = match InMemSignalProtocolStore::new(identity, registration_id) {
        Ok(store) => store,
        Err(_) => return ptr::null_mut(),
    };

    Box::into_raw(Box::new(SignalGoProtocolStore { inner: store }))
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_protocol_store_free(ptr: *mut SignalGoProtocolStore) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_ciphertext_message_get_type(
    message: *const SignalGoCiphertextMessage,
) -> u8 {
    if message.is_null() {
        return 0;
    }
    let message = unsafe { &(*message).inner };
    message.message_type() as u8
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_ciphertext_message_serialize(
    message: *const SignalGoCiphertextMessage,
    out_len: *mut usize,
) -> *mut u8 {
    if message.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }
    let message = unsafe { &(*message).inner };
    let mut bytes = message.serialize().to_vec();
    let len = bytes.len();
    let ptr = bytes.as_mut_ptr();
    unsafe {
        *out_len = len;
    }
    std::mem::forget(bytes);
    ptr
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_ciphertext_message_free(ptr: *mut SignalGoCiphertextMessage) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_signal_message_from_bytes(
    data: *const u8,
    len: usize,
) -> *mut SignalGoSignalMessage {
    if data.is_null() {
        return ptr::null_mut();
    }
    let data = unsafe { std::slice::from_raw_parts(data, len) };
    match SignalMessage::try_from(data) {
        Ok(message) => Box::into_raw(Box::new(SignalGoSignalMessage { inner: message })),
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_signal_message_free(ptr: *mut SignalGoSignalMessage) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_signal_message_from_bytes(
    data: *const u8,
    len: usize,
) -> *mut SignalGoPreKeySignalMessage {
    if data.is_null() {
        return ptr::null_mut();
    }
    let data = unsafe { std::slice::from_raw_parts(data, len) };
    match PreKeySignalMessage::try_from(data) {
        Ok(message) => Box::into_raw(Box::new(SignalGoPreKeySignalMessage { inner: message })),
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_signal_message_free(ptr: *mut SignalGoPreKeySignalMessage) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_buffer_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Vec::from_raw_parts(ptr, len, len);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_store_encrypt_message(
    store: *mut SignalGoProtocolStore,
    address: *const SignalGoProtocolAddress,
    plaintext: *const u8,
    plaintext_len: usize,
    now_millis: u64,
    out: *mut *mut SignalGoCiphertextMessage,
) -> i32 {
    if store.is_null() || address.is_null() || plaintext.is_null() || out.is_null() {
        return -1;
    }

    let plaintext = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let store_ref = unsafe { &mut (*store).inner };
    let address = unsafe { &(*address).inner };
    let now = system_time_from_millis(now_millis);
    let mut rng = os_rng();

    let store_ptr: *mut InMemSignalProtocolStore = store_ref;

    // The async API requires Rust futures; block here so the FFI stays synchronous.
    let result = block_on(message_encrypt(
        plaintext,
        address,
        unsafe { &mut *store_ptr } as &mut dyn SessionStore,
        unsafe { &mut *store_ptr } as &mut dyn IdentityKeyStore,
        now,
        &mut rng,
    ));

    match result {
        Ok(ciphertext) => {
            unsafe {
                *out = Box::into_raw(Box::new(SignalGoCiphertextMessage { inner: ciphertext }));
            }
            0
        }
        Err(err) => error_code(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_store_decrypt_signal_message(
    store: *mut SignalGoProtocolStore,
    address: *const SignalGoProtocolAddress,
    message: *const SignalGoSignalMessage,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if store.is_null()
        || address.is_null()
        || message.is_null()
        || out_ptr.is_null()
        || out_len.is_null()
    {
        return -1;
    }

    let store_ref = unsafe { &mut (*store).inner };
    let address = unsafe { &(*address).inner };
    let message = unsafe { &(*message).inner };
    let mut rng = os_rng();

    let store_ptr: *mut InMemSignalProtocolStore = store_ref;

    // Session state updates happen inside the future, so block until it completes.
    let result = block_on(message_decrypt_signal(
        message,
        address,
        unsafe { &mut *store_ptr } as &mut dyn SessionStore,
        unsafe { &mut *store_ptr } as &mut dyn IdentityKeyStore,
        &mut rng,
    ));

    match result {
        Ok(mut plaintext) => {
            let len = plaintext.len();
            let ptr = plaintext.as_mut_ptr();
            unsafe {
                *out_ptr = ptr;
                *out_len = len;
            }
            std::mem::forget(plaintext);
            0
        }
        Err(err) => error_code(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_store_decrypt_prekey_message(
    store: *mut SignalGoProtocolStore,
    address: *const SignalGoProtocolAddress,
    message: *const SignalGoPreKeySignalMessage,
    use_pq_ratchet: bool,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if store.is_null()
        || address.is_null()
        || message.is_null()
        || out_ptr.is_null()
        || out_len.is_null()
    {
        return -1;
    }

    let store_ref = unsafe { &mut (*store).inner };
    let address = unsafe { &(*address).inner };
    let message = unsafe { &(*message).inner };
    let mut rng = os_rng();

    let store_ptr: *mut InMemSignalProtocolStore = store_ref;

    // Pre-key decrypt touches multiple stores; block so we can return the plaintext.
    let result = block_on(message_decrypt_prekey(
        message,
        address,
        unsafe { &mut *store_ptr } as &mut dyn SessionStore,
        unsafe { &mut *store_ptr } as &mut dyn IdentityKeyStore,
        unsafe { &mut *store_ptr } as &mut dyn PreKeyStore,
        unsafe { &mut *store_ptr } as &mut dyn SignedPreKeyStore,
        unsafe { &mut *store_ptr } as &mut dyn KyberPreKeyStore,
        &mut rng,
        UsePQRatchet::from(use_pq_ratchet),
    ));

    match result {
        Ok(mut plaintext) => {
            let len = plaintext.len();
            let ptr = plaintext.as_mut_ptr();
            unsafe {
                *out_ptr = ptr;
                *out_len = len;
            }
            std::mem::forget(plaintext);
            0
        }
        Err(err) => error_code(err),
    }
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub extern "C" fn signalgo_store_generate_prekey_bundle(
    store: *mut SignalGoProtocolStore,
    registration_id: u32,
    device_id: u32,
    prekey_id: u32,
    signed_prekey_id: u32,
    kyber_prekey_id: u32,
    out_bundle: *mut *mut SignalGoPreKeyBundle,
) -> i32 {
    if store.is_null() || out_bundle.is_null() {
        return -1;
    }

    let store_ref = unsafe { &mut (*store).inner };

    // Grab the identity key first; it signs both EC and Kyber pre-keys we publish.
    let identity = match block_on(store_ref.get_identity_key_pair()) {
        Ok(identity) => identity,
        Err(err) => return error_code(err),
    };

    let mut rng = os_rng();

    // Generate one-time EC pre-key
    let ec_pre_key_pair = KeyPair::generate(&mut rng);
    let pre_key_id = PreKeyId::from(prekey_id);
    let pre_key_record = PreKeyRecord::new(pre_key_id, &ec_pre_key_pair);
    if let Err(err) = block_on(store_ref.save_pre_key(pre_key_id, &pre_key_record)) {
        return error_code(err);
    }

    // Signed pre-key
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let signature = match identity
        .private_key()
        .calculate_signature(&signed_pre_key_pair.public_key.serialize(), &mut rng)
    {
        Ok(sig) => sig,
        Err(_) => return -1,
    };
    let signature = signature.into_vec();
    let timestamp = timestamp_now();
    let signed_pre_key_id = SignedPreKeyId::from(signed_prekey_id);
    let signed_pre_key_record = SignedPreKeyRecord::new(
        signed_pre_key_id,
        timestamp,
        &signed_pre_key_pair,
        &signature,
    );
    if let Err(err) =
        block_on(store_ref.save_signed_pre_key(signed_pre_key_id, &signed_pre_key_record))
    {
        return error_code(err);
    }

    // Kyber pre-key
    let kyber_pre_key_id = KyberPreKeyId::from(kyber_prekey_id);
    let kyber_pre_key_record =
        match KyberPreKeyRecord::generate(KYBER_KEY_TYPE, kyber_pre_key_id, identity.private_key())
        {
            Ok(record) => record,
            Err(_) => return -1,
        };
    if let Err(err) =
        block_on(store_ref.save_kyber_pre_key(kyber_pre_key_id, &kyber_pre_key_record))
    {
        return error_code(err);
    }

    let device_id = match DeviceId::try_from(device_id) {
        Ok(id) => id,
        Err(_) => return -1,
    };

    let prekey_public = match pre_key_record.public_key() {
        Ok(key) => key,
        Err(err) => return error_code(err),
    };

    let signed_prekey_signature = signature.clone();

    let kyber_public = match kyber_pre_key_record.public_key() {
        Ok(key) => key.clone(),
        Err(err) => return error_code(err),
    };
    let kyber_signature = match kyber_pre_key_record.signature() {
        Ok(sig) => sig,
        Err(err) => return error_code(err),
    };

    let bundle = match PreKeyBundle::new(
        registration_id,
        device_id,
        Some((pre_key_id, prekey_public)),
        signed_pre_key_id,
        signed_pre_key_pair.public_key,
        signed_prekey_signature,
        kyber_pre_key_id,
        kyber_public,
        kyber_signature,
        IdentityKey::new(*identity.public_key()),
    ) {
        Ok(bundle) => bundle,
        Err(err) => return error_code(err),
    };

    unsafe {
        *out_bundle = Box::into_raw(Box::new(SignalGoPreKeyBundle { inner: bundle }));
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_free(ptr: *mut SignalGoPreKeyBundle) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_get_registration_id(
    bundle: *const SignalGoPreKeyBundle,
    out: *mut u32,
) -> i32 {
    if bundle.is_null() || out.is_null() {
        return -1;
    }

    let registration_id = match unsafe { (*bundle).inner.registration_id() } {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    unsafe {
        *out = registration_id;
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_get_device_id(
    bundle: *const SignalGoPreKeyBundle,
    out: *mut u32,
) -> i32 {
    if bundle.is_null() || out.is_null() {
        return -1;
    }

    let device_id = match unsafe { (*bundle).inner.device_id() } {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    unsafe {
        *out = u32::from(device_id);
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_get_prekey_id(
    bundle: *const SignalGoPreKeyBundle,
    present: *mut bool,
    out_id: *mut u32,
) -> i32 {
    if bundle.is_null() || present.is_null() || out_id.is_null() {
        return -1;
    }

    let pre_key_id = match unsafe { (*bundle).inner.pre_key_id() } {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    unsafe {
        match pre_key_id {
            Some(id) => {
                *present = true;
                *out_id = id.into();
            }
            None => {
                *present = false;
                *out_id = 0;
            }
        }
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_get_prekey_public(
    bundle: *const SignalGoPreKeyBundle,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if bundle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return -1;
    }

    let key = match unsafe { (*bundle).inner.pre_key_public() } {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    match key {
        Some(public_key) => {
            let mut bytes = public_key.serialize();
            let len = bytes.len();
            let ptr = bytes.as_mut_ptr();
            unsafe {
                *out_ptr = ptr;
                *out_len = len;
            }
            std::mem::forget(bytes);
        }
        None => unsafe {
            *out_ptr = ptr::null_mut();
            *out_len = 0;
        },
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_get_signed_prekey_id(
    bundle: *const SignalGoPreKeyBundle,
    out: *mut u32,
) -> i32 {
    if bundle.is_null() || out.is_null() {
        return -1;
    }

    let id = match unsafe { (*bundle).inner.signed_pre_key_id() } {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    unsafe {
        *out = id.into();
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_get_signed_prekey_public(
    bundle: *const SignalGoPreKeyBundle,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if bundle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return -1;
    }

    let public_key = match unsafe { (*bundle).inner.signed_pre_key_public() } {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    let mut bytes = public_key.serialize();
    let len = bytes.len();
    let ptr = bytes.as_mut_ptr();
    unsafe {
        *out_ptr = ptr;
        *out_len = len;
    }
    std::mem::forget(bytes);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_get_signed_prekey_signature(
    bundle: *const SignalGoPreKeyBundle,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if bundle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return -1;
    }

    let signature = match unsafe { (*bundle).inner.signed_pre_key_signature() } {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    let mut bytes = signature.to_vec().into_boxed_slice();
    let len = bytes.len();
    let ptr = bytes.as_mut_ptr();
    unsafe {
        *out_ptr = ptr;
        *out_len = len;
    }
    std::mem::forget(bytes);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_get_identity_key(
    bundle: *const SignalGoPreKeyBundle,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if bundle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return -1;
    }

    let identity_key = match unsafe { (*bundle).inner.identity_key() } {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    let mut bytes = identity_key.serialize();
    let len = bytes.len();
    let ptr = bytes.as_mut_ptr();
    unsafe {
        *out_ptr = ptr;
        *out_len = len;
    }
    std::mem::forget(bytes);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_get_kyber_prekey_id(
    bundle: *const SignalGoPreKeyBundle,
    out: *mut u32,
) -> i32 {
    if bundle.is_null() || out.is_null() {
        return -1;
    }

    let id = match unsafe { (*bundle).inner.kyber_pre_key_id() } {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    unsafe {
        *out = id.into();
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_get_kyber_prekey_public(
    bundle: *const SignalGoPreKeyBundle,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if bundle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return -1;
    }

    let public_key = match unsafe { (*bundle).inner.kyber_pre_key_public() } {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    let mut bytes = public_key.serialize();
    let len = bytes.len();
    let ptr = bytes.as_mut_ptr();
    unsafe {
        *out_ptr = ptr;
        *out_len = len;
    }
    std::mem::forget(bytes);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_get_kyber_prekey_signature(
    bundle: *const SignalGoPreKeyBundle,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if bundle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return -1;
    }

    let signature = match unsafe { (*bundle).inner.kyber_pre_key_signature() } {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    let mut bytes = signature.to_vec().into_boxed_slice();
    let len = bytes.len();
    let ptr = bytes.as_mut_ptr();
    unsafe {
        *out_ptr = ptr;
        *out_len = len;
    }
    std::mem::forget(bytes);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_prekey_bundle_from_parts(
    registration_id: u32,
    device_id: u32,
    has_pre_key: bool,
    pre_key_id: u32,
    pre_key_public: *const u8,
    pre_key_public_len: usize,
    signed_pre_key_id: u32,
    signed_pre_key_public: *const u8,
    signed_pre_key_public_len: usize,
    signed_pre_key_signature: *const u8,
    signed_pre_key_signature_len: usize,
    identity_key: *const u8,
    identity_key_len: usize,
    kyber_pre_key_id: u32,
    kyber_pre_key_public: *const u8,
    kyber_pre_key_public_len: usize,
    kyber_pre_key_signature: *const u8,
    kyber_pre_key_signature_len: usize,
    out_bundle: *mut *mut SignalGoPreKeyBundle,
) -> i32 {
    if out_bundle.is_null() {
        return -1;
    }

    if signed_pre_key_public.is_null()
        || signed_pre_key_signature.is_null()
        || identity_key.is_null()
        || kyber_pre_key_public.is_null()
        || kyber_pre_key_signature.is_null()
    {
        return -1;
    }

    let device_id = match DeviceId::try_from(device_id) {
        Ok(id) => id,
        Err(_) => return -1,
    };

    let signed_pre_key_id = SignedPreKeyId::from(signed_pre_key_id);
    let kyber_pre_key_id = KyberPreKeyId::from(kyber_pre_key_id);

    let signed_pre_key_public =
        unsafe { std::slice::from_raw_parts(signed_pre_key_public, signed_pre_key_public_len) };
    let signed_pre_key_public = match libsignal_protocol::PublicKey::try_from(signed_pre_key_public)
    {
        Ok(value) => value,
        Err(err) => return error_code(err.into()),
    };

    let signed_pre_key_signature = unsafe {
        std::slice::from_raw_parts(signed_pre_key_signature, signed_pre_key_signature_len)
    }
    .to_vec();

    let identity_key_bytes = unsafe { std::slice::from_raw_parts(identity_key, identity_key_len) };
    let identity_key = match IdentityKey::try_from(identity_key_bytes) {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    let kyber_pre_key_public =
        unsafe { std::slice::from_raw_parts(kyber_pre_key_public, kyber_pre_key_public_len) };
    let kyber_pre_key_public = match kem::PublicKey::deserialize(kyber_pre_key_public) {
        Ok(value) => value,
        Err(err) => return error_code(err),
    };

    let kyber_pre_key_signature =
        unsafe { std::slice::from_raw_parts(kyber_pre_key_signature, kyber_pre_key_signature_len) }
            .to_vec();

    let pre_key = if has_pre_key {
        if pre_key_public.is_null() {
            return -1;
        }
        let pre_key_public =
            unsafe { std::slice::from_raw_parts(pre_key_public, pre_key_public_len) };
        let pre_key_public = match libsignal_protocol::PublicKey::try_from(pre_key_public) {
            Ok(value) => value,
            Err(err) => return error_code(err.into()),
        };
        Some((PreKeyId::from(pre_key_id), pre_key_public))
    } else {
        None
    };

    let bundle = match PreKeyBundle::new(
        registration_id,
        device_id,
        pre_key,
        signed_pre_key_id,
        signed_pre_key_public,
        signed_pre_key_signature,
        kyber_pre_key_id,
        kyber_pre_key_public,
        kyber_pre_key_signature,
        identity_key,
    ) {
        Ok(bundle) => bundle,
        Err(err) => return error_code(err),
    };

    unsafe {
        *out_bundle = Box::into_raw(Box::new(SignalGoPreKeyBundle { inner: bundle }));
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn signalgo_store_process_prekey_bundle(
    store: *mut SignalGoProtocolStore,
    address: *const SignalGoProtocolAddress,
    bundle: *const SignalGoPreKeyBundle,
    now_millis: u64,
    use_pq_ratchet: bool,
) -> i32 {
    if store.is_null() || address.is_null() || bundle.is_null() {
        return -1;
    }

    let store_ref = unsafe { &mut (*store).inner };
    let address = unsafe { &(*address).inner };
    let bundle = unsafe { &(*bundle).inner };
    let now = system_time_from_millis(now_millis);
    let mut rng = os_rng();

    let store_ptr: *mut InMemSignalProtocolStore = store_ref;

    let result = block_on(process_prekey_bundle(
        address,
        unsafe { &mut *store_ptr } as &mut dyn SessionStore,
        unsafe { &mut *store_ptr } as &mut dyn IdentityKeyStore,
        bundle,
        now,
        &mut rng,
        UsePQRatchet::from(use_pq_ratchet),
    ));

    match result {
        Ok(()) => 0,
        Err(err) => error_code(err),
    }
}
