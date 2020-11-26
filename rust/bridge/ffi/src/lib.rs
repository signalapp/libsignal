//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(warnings)]

use async_trait::async_trait;
use libc::{c_char, c_int, c_uchar, c_uint, c_ulonglong, size_t};
use libsignal_protocol_rust::*;
use static_assertions::const_assert_eq;
use std::convert::TryFrom;
use std::ffi::{c_void, CString};

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

#[no_mangle]
pub unsafe extern "C" fn signal_address_new(
    address: *mut *mut ProtocolAddress,
    name: *const c_char,
    device_id: c_uint,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let name = read_c_string(name)?;
        box_object(address, Ok(ProtocolAddress::new(name, device_id)))
    })
}

ffi_fn_get_cstring!(signal_address_get_name(ProtocolAddress) using
                    |p: &ProtocolAddress| Ok(p.name().to_string()));

ffi_fn_get_uint32!(signal_address_get_device_id(ProtocolAddress) using
                   |obj: &ProtocolAddress| { Ok(obj.device_id()) });

ffi_fn_destroy!(signal_address_destroy destroys ProtocolAddress);

ffi_fn_clone!(signal_address_clone clones ProtocolAddress);

ffi_fn_deserialize!(signal_publickey_deserialize(PublicKey) is PublicKey::deserialize);

ffi_fn_get_bytearray!(signal_publickey_serialize(PublicKey) using |k: &PublicKey| Ok(k.serialize()));

ffi_fn_get_bytearray!(signal_publickey_get_public_key_bytes(PublicKey) using |k: &PublicKey| Ok(k.public_key_bytes()?.to_vec()));

#[no_mangle]
pub unsafe extern "C" fn signal_publickey_compare(
    result: *mut i32,
    key1: *const PublicKey,
    key2: *const PublicKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let key1 = native_handle_cast::<PublicKey>(key1)?;
        let key2 = native_handle_cast::<PublicKey>(key2)?;

        *result = match key1.cmp(&key2) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        };
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_publickey_verify(
    key: *const PublicKey,
    result: *mut bool,
    message: *const c_uchar,
    message_len: size_t,
    signature: *const c_uchar,
    signature_len: size_t,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        *result = false; // pre-set to invalid state
        let key = native_handle_cast::<PublicKey>(key)?;
        let message = as_slice(message, message_len)?;
        let signature = as_slice(signature, signature_len)?;

        *result = key.verify_signature(&message, &signature)?;
        Ok(())
    })
}

ffi_fn_destroy!(signal_publickey_destroy destroys PublicKey);

ffi_fn_clone!(signal_publickey_clone clones PublicKey);

ffi_fn_deserialize!(signal_privatekey_deserialize(PrivateKey) is PrivateKey::deserialize);

ffi_fn_get_bytearray!(signal_privatekey_serialize(PrivateKey) using
                      |k: &PrivateKey| Ok(k.serialize()));

#[no_mangle]
pub unsafe extern "C" fn signal_privatekey_generate(
    key: *mut *mut PrivateKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let mut rng = rand::rngs::OsRng;
        let keypair = KeyPair::generate(&mut rng);
        box_object::<PrivateKey>(key, Ok(keypair.private_key))
    })
}

ffi_fn_get_new_boxed_obj!(signal_privatekey_get_public_key(PublicKey) from PrivateKey,
                          |k: &PrivateKey| k.public_key());

#[no_mangle]
pub unsafe extern "C" fn signal_privatekey_sign(
    signature: *mut *const c_uchar,
    signature_len: *mut size_t,
    key: *const PrivateKey,
    message: *const c_uchar,
    message_len: size_t,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let message = as_slice(message, message_len)?;
        let key = native_handle_cast::<PrivateKey>(key)?;
        let mut rng = rand::rngs::OsRng;
        let sig = key.calculate_signature(&message, &mut rng);
        write_bytearray_to(signature, signature_len, sig)
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_privatekey_agree(
    shared_secret: *mut *const c_uchar,
    shared_secret_len: *mut size_t,
    private_key: *const PrivateKey,
    public_key: *const PublicKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let private_key = native_handle_cast::<PrivateKey>(private_key)?;
        let public_key = native_handle_cast::<PublicKey>(public_key)?;
        let dh_secret = private_key.calculate_agreement(&public_key);
        write_bytearray_to(shared_secret, shared_secret_len, dh_secret)
    })
}

ffi_fn_destroy!(signal_privatekey_destroy destroys PrivateKey);

ffi_fn_clone!(signal_privatekey_clone clones PrivateKey);

#[no_mangle]
pub unsafe extern "C" fn signal_identitykeypair_serialize(
    output: *mut *const c_uchar,
    output_len: *mut size_t,
    private_key: *const PrivateKey,
    public_key: *const PublicKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let private_key = *native_handle_cast::<PrivateKey>(private_key)?;
        let public_key = *native_handle_cast::<PublicKey>(public_key)?;
        let identity_key_pair = IdentityKeyPair::new(IdentityKey::new(public_key), private_key);
        write_bytearray_to(output, output_len, Ok(identity_key_pair.serialize()))
    })
}

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

ffi_fn_deserialize!(signal_session_record_deserialize(SessionRecord) is SessionRecord::deserialize);

ffi_fn_get_bytearray!(signal_session_record_serialize(SessionRecord) using
                      |s: &SessionRecord| s.serialize());

ffi_fn_get_uint32!(signal_session_record_get_remote_registration_id(SessionRecord) using
                   |s: &SessionRecord| s.session_state()?.remote_registration_id());

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

ffi_fn_destroy!(signal_session_record_destroy destroys SessionRecord);

ffi_fn_clone!(signal_session_record_clone clones SessionRecord);

#[no_mangle]
pub unsafe extern "C" fn signal_fingerprint_format(
    fprint: *mut *const c_char,
    local: *const c_uchar,
    local_len: size_t,
    remote: *const c_uchar,
    remote_len: size_t,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let local = as_slice(local, local_len)?;
        let remote = as_slice(remote, remote_len)?;
        let fingerprint = DisplayableFingerprint::new(&local, &remote).map(|f| format!("{}", f));
        write_cstr_to(fprint, fingerprint)
    })
}

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

ffi_fn_destroy!(signal_fingerprint_destroy destroys Fingerprint);

ffi_fn_clone!(signal_fingerprint_clone clones Fingerprint);

ffi_fn_get_cstring!(signal_fingerprint_display_string(Fingerprint) using Fingerprint::display_string);

ffi_fn_get_bytearray!(signal_fingerprint_scannable_encoding(Fingerprint) using
                      |f: &Fingerprint| f.scannable.serialize());

#[no_mangle]
pub unsafe extern "C" fn signal_fingerprint_compare(
    result: *mut bool,
    fprint1: *const c_uchar,
    fprint1_len: size_t,
    fprint2: *const c_uchar,
    fprint2_len: size_t,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        if fprint1.is_null() || fprint2.is_null() || result.is_null() {
            return Err(SignalFfiError::NullPointer);
        }
        let fprint1 = as_slice(fprint1, fprint1_len)?;
        let fprint2 = as_slice(fprint2, fprint2_len)?;

        let fprint1 = ScannableFingerprint::deserialize(&fprint1)?;
        *result = fprint1.compare(&fprint2)?;
        Ok(())
    })
}

ffi_fn_deserialize!(signal_message_deserialize(SignalMessage) is SignalMessage::try_from);

#[no_mangle]
pub unsafe extern "C" fn signal_message_new(
    obj: *mut *mut SignalMessage,
    message_version: c_uchar,
    mac_key: *const c_uchar,
    mac_key_len: size_t,
    sender_ratchet_key: *const PublicKey,
    counter: c_uint,
    previous_counter: c_uint,
    ciphertext: *const c_uchar,
    ciphertext_len: size_t,
    sender_identity_key: *const PublicKey,
    receiver_identity_key: *const PublicKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let mac_key = as_slice(mac_key, mac_key_len)?;
        let sender_ratchet_key = native_handle_cast::<PublicKey>(sender_ratchet_key)?;
        let ciphertext = as_slice(ciphertext, ciphertext_len)?;

        let sender_identity_key = native_handle_cast::<PublicKey>(sender_identity_key)?;
        let receiver_identity_key = native_handle_cast::<PublicKey>(receiver_identity_key)?;

        let msg = SignalMessage::new(
            message_version,
            &mac_key,
            *sender_ratchet_key,
            counter,
            previous_counter,
            &ciphertext,
            &IdentityKey::new(*sender_identity_key),
            &IdentityKey::new(*receiver_identity_key),
        );

        box_object::<SignalMessage>(obj, msg)
    })
}

ffi_fn_destroy!(signal_message_destroy destroys SignalMessage);

ffi_fn_clone!(signal_message_clone clones SignalMessage);

ffi_fn_get_new_boxed_obj!(signal_message_get_sender_ratchet_key(PublicKey) from SignalMessage,
                          |p: &SignalMessage| Ok(*p.sender_ratchet_key()));

ffi_fn_get_bytearray!(signal_message_get_body(SignalMessage) using
                      |m: &SignalMessage| Ok(m.body().to_vec()));
ffi_fn_get_bytearray!(signal_message_get_serialized(SignalMessage) using
                      |m: &SignalMessage| Ok(m.serialized().to_vec()));

ffi_fn_get_uint32!(signal_message_get_message_version(SignalMessage) using
                   |msg: &SignalMessage| { Ok(msg.message_version() as u32) });

ffi_fn_get_uint32!(signal_message_get_counter(SignalMessage) using
                   |msg: &SignalMessage| { Ok(msg.counter()) });

#[no_mangle]
pub unsafe extern "C" fn signal_message_verify_mac(
    result: *mut bool,
    handle: *const SignalMessage,
    sender_identity_key: *const PublicKey,
    receiver_identity_key: *const PublicKey,
    mac_key: *const c_uchar,
    mac_key_len: size_t,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let msg = native_handle_cast::<SignalMessage>(handle)?;
        let sender_identity_key = native_handle_cast::<PublicKey>(sender_identity_key)?;
        let receiver_identity_key = native_handle_cast::<PublicKey>(receiver_identity_key)?;
        let mac_key = as_slice(mac_key, mac_key_len)?;

        *result = msg.verify_mac(
            &IdentityKey::new(*sender_identity_key),
            &IdentityKey::new(*receiver_identity_key),
            &mac_key,
        )?;
        Ok(())
    })
}

ffi_fn_deserialize!(signal_pre_key_signal_message_deserialize(PreKeySignalMessage) is PreKeySignalMessage::try_from);

#[no_mangle]
pub unsafe extern "C" fn signal_pre_key_signal_message_new(
    obj: *mut *mut PreKeySignalMessage,
    message_version: c_uchar,
    registration_id: c_uint,
    pre_key_id: *const c_uint,
    signed_pre_key_id: c_uint,
    base_key: *const PublicKey,
    identity_key: *const PublicKey,
    signal_message: *const SignalMessage,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let pre_key_id = get_optional_uint32(pre_key_id);
        let base_key = native_handle_cast::<PublicKey>(base_key)?;
        let identity_key = native_handle_cast::<PublicKey>(identity_key)?;
        let signal_message = native_handle_cast::<SignalMessage>(signal_message)?;

        let msg = PreKeySignalMessage::new(
            message_version,
            registration_id,
            pre_key_id,
            signed_pre_key_id,
            *base_key,
            IdentityKey::new(*identity_key),
            signal_message.clone(),
        );
        box_object::<PreKeySignalMessage>(obj, msg)
    })
}

ffi_fn_destroy!(signal_pre_key_signal_message_destroy destroys PreKeySignalMessage);

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

ffi_fn_get_bytearray!(signal_pre_key_signal_message_serialize(PreKeySignalMessage) using
                      |m: &PreKeySignalMessage| Ok(m.serialized().to_vec()));

#[no_mangle]
pub unsafe extern "C" fn signal_sender_key_message_new(
    obj: *mut *mut SenderKeyMessage,
    key_id: c_uint,
    iteration: c_uint,
    ciphertext: *const c_uchar,
    ciphertext_len: size_t,
    pk: *const PrivateKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let ciphertext = as_slice(ciphertext, ciphertext_len)?;
        let signature_key = native_handle_cast::<PrivateKey>(pk)?;
        let mut csprng = rand::rngs::OsRng;
        let skm = SenderKeyMessage::new(key_id, iteration, &ciphertext, &mut csprng, signature_key);
        box_object::<SenderKeyMessage>(obj, skm)
    })
}

ffi_fn_deserialize!(signal_sender_key_message_deserialize(SenderKeyMessage) is SenderKeyMessage::try_from);

ffi_fn_destroy!(signal_sender_key_message_destroy destroys SenderKeyMessage);

ffi_fn_clone!(signal_sender_key_message_clone clones SenderKeyMessage);

ffi_fn_get_uint32!(signal_sender_key_message_get_key_id(SenderKeyMessage) using
                   |m: &SenderKeyMessage| Ok(m.key_id()));

ffi_fn_get_uint32!(signal_sender_key_message_get_iteration(SenderKeyMessage) using
                   |m: &SenderKeyMessage| Ok(m.iteration()));

ffi_fn_get_bytearray!(signal_sender_key_message_get_cipher_text(SenderKeyMessage) using
                      |m: &SenderKeyMessage| Ok(m.ciphertext().to_vec()));

ffi_fn_get_bytearray!(signal_sender_key_message_serialize(SenderKeyMessage) using
                      |m: &SenderKeyMessage| Ok(m.serialized().to_vec()));

#[no_mangle]
pub unsafe extern "C" fn signal_sender_key_message_verify_signature(
    result: *mut bool,
    skm: *const SenderKeyMessage,
    pubkey: *const PublicKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let skm = native_handle_cast::<SenderKeyMessage>(skm)?;
        let pubkey = native_handle_cast::<PublicKey>(pubkey)?;

        *result = skm.verify_signature(pubkey)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_sender_key_distribution_message_new(
    obj: *mut *mut SenderKeyDistributionMessage,
    key_id: c_uint,
    iteration: c_uint,
    chainkey: *const c_uchar,
    chainkey_len: size_t,
    pk: *const PublicKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let chainkey = as_slice(chainkey, chainkey_len)?;
        let signature_key = native_handle_cast::<PublicKey>(pk)?;
        let skdm = SenderKeyDistributionMessage::new(key_id, iteration, &chainkey, *signature_key);
        box_object::<SenderKeyDistributionMessage>(obj, skdm)
    })
}

ffi_fn_deserialize!(signal_sender_key_distribution_message_deserialize(SenderKeyDistributionMessage) is SenderKeyDistributionMessage::try_from);

ffi_fn_destroy!(signal_sender_key_distribution_message_destroy destroys SenderKeyDistributionMessage);

ffi_fn_clone!(signal_sender_key_distribution_message_clone clones SenderKeyDistributionMessage);

ffi_fn_get_uint32!(signal_sender_key_distribution_message_get_id(SenderKeyDistributionMessage) using
                   |m: &SenderKeyDistributionMessage| m.id());

ffi_fn_get_uint32!(signal_sender_key_distribution_message_get_iteration(SenderKeyDistributionMessage) using
                   |m: &SenderKeyDistributionMessage| m.iteration());

ffi_fn_get_bytearray!(signal_sender_key_distribution_message_get_chain_key(SenderKeyDistributionMessage) using
                      |m: &SenderKeyDistributionMessage| Ok(m.chain_key()?.to_vec()));

ffi_fn_get_new_boxed_obj!(signal_sender_key_distribution_message_get_signature_key(PublicKey) from SenderKeyDistributionMessage,
                          |m: &SenderKeyDistributionMessage| Ok(*m.signing_key()?));

ffi_fn_get_bytearray!(signal_sender_key_distribution_message_serialize(SenderKeyDistributionMessage) using
                      |m: &SenderKeyDistributionMessage| Ok(m.serialized().to_vec()));

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

        let prekey = native_handle_cast_optional::<PublicKey>(prekey)?.copied();

        let prekey_id = get_optional_uint32(prekey_id);
        let identity_key = IdentityKey::new(*(identity_key as *const PublicKey));

        let bundle = PreKeyBundle::new(
            registration_id,
            device_id,
            prekey_id,
            prekey,
            signed_prekey_id,
            *signed_prekey,
            signed_prekey_signature.to_vec(),
            identity_key,
        );

        box_object::<PreKeyBundle>(obj, bundle)
    })
}

ffi_fn_destroy!(signal_pre_key_bundle_destroy destroys PreKeyBundle);

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

ffi_fn_get_bytearray!(signal_pre_key_bundle_get_signed_pre_key_signature(PreKeyBundle) using
                      |m: &PreKeyBundle| Ok(m.signed_pre_key_signature()?.to_vec()));

/* SignedPreKeyRecord */

#[no_mangle]
pub unsafe extern "C" fn signal_signed_pre_key_record_new(
    obj: *mut *mut SignedPreKeyRecord,
    id: c_uint,
    timestamp: c_ulonglong,
    pub_key: *const PublicKey,
    priv_key: *const PrivateKey,
    signature: *const c_uchar,
    signature_len: size_t,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let pub_key = native_handle_cast::<PublicKey>(pub_key)?;
        let priv_key = native_handle_cast::<PrivateKey>(priv_key)?;
        let id = id;
        let timestamp = timestamp as u64;
        let keypair = KeyPair::new(*pub_key, *priv_key);
        let signature = as_slice(signature, signature_len)?;

        let spkr = SignedPreKeyRecord::new(id, timestamp, &keypair, &signature);

        box_object::<SignedPreKeyRecord>(obj, Ok(spkr))
    })
}

ffi_fn_deserialize!(signal_signed_pre_key_record_deserialize(SignedPreKeyRecord) is SignedPreKeyRecord::deserialize);

ffi_fn_get_uint32!(signal_signed_pre_key_record_get_id(SignedPreKeyRecord) using
                   |m: &SignedPreKeyRecord| m.id());

ffi_fn_get_uint64!(signal_signed_pre_key_record_get_timestamp(SignedPreKeyRecord) using
                   |m: &SignedPreKeyRecord| m.timestamp());

ffi_fn_get_new_boxed_obj!(signal_signed_pre_key_record_get_public_key(PublicKey) from SignedPreKeyRecord,
                          |p: &SignedPreKeyRecord| p.public_key());

ffi_fn_get_new_boxed_obj!(signal_signed_pre_key_record_get_private_key(PrivateKey) from SignedPreKeyRecord,
                          |p: &SignedPreKeyRecord| p.private_key());

ffi_fn_get_bytearray!(signal_signed_pre_key_record_get_signature(SignedPreKeyRecord) using
                      |m: &SignedPreKeyRecord| m.signature());

ffi_fn_get_bytearray!(signal_signed_pre_key_record_serialize(SignedPreKeyRecord) using
                      |m: &SignedPreKeyRecord| m.serialize());

ffi_fn_destroy!(signal_signed_pre_key_record_destroy destroys SignedPreKeyRecord);

ffi_fn_clone!(signal_signed_pre_key_record_clone clones SignedPreKeyRecord);

/* PreKeyRecord */

#[no_mangle]
pub unsafe extern "C" fn signal_pre_key_record_new(
    obj: *mut *mut PreKeyRecord,
    id: c_uint,
    pub_key: *const PublicKey,
    priv_key: *const PrivateKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let id = id;
        let pub_key = native_handle_cast::<PublicKey>(pub_key)?;
        let priv_key = native_handle_cast::<PrivateKey>(priv_key)?;
        let keypair = KeyPair::new(*pub_key, *priv_key);

        let pkr = PreKeyRecord::new(id, &keypair);

        box_object::<PreKeyRecord>(obj, Ok(pkr))
    })
}

ffi_fn_deserialize!(signal_pre_key_record_deserialize(PreKeyRecord) is PreKeyRecord::deserialize);

ffi_fn_get_uint32!(signal_pre_key_record_get_id(PreKeyRecord) using
                   |m: &PreKeyRecord| m.id());

ffi_fn_get_new_boxed_obj!(signal_pre_key_record_get_public_key(PublicKey) from PreKeyRecord,
                          |p: &PreKeyRecord| p.public_key());

ffi_fn_get_new_boxed_obj!(signal_pre_key_record_get_private_key(PrivateKey) from PreKeyRecord,
                          |p: &PreKeyRecord| p.private_key());

ffi_fn_get_bytearray!(signal_pre_key_record_serialize(PreKeyRecord) using
                      |m: &PreKeyRecord| m.serialize());

ffi_fn_destroy!(signal_pre_key_record_destroy destroys PreKeyRecord);

ffi_fn_clone!(signal_pre_key_record_clone clones PreKeyRecord);

/* SenderKeyName */
#[no_mangle]
pub unsafe extern "C" fn signal_sender_key_name_new(
    obj: *mut *mut SenderKeyName,
    group_id: *const c_char,
    sender_name: *const c_char,
    sender_device_id: c_uint,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let group_id = read_c_string(group_id)?;
        let sender_name = read_c_string(sender_name)?;
        let name = SenderKeyName::new(
            group_id,
            ProtocolAddress::new(sender_name, sender_device_id),
        );
        box_object::<SenderKeyName>(obj, name)
    })
}

ffi_fn_destroy!(signal_sender_key_name_destroy destroys SenderKeyName);

ffi_fn_clone!(signal_sender_key_name_clone clones SenderKeyName);

ffi_fn_get_cstring!(signal_sender_key_name_get_group_id(SenderKeyName) using
                    SenderKeyName::group_id);

ffi_fn_get_cstring!(signal_sender_key_name_get_sender_name(SenderKeyName) using
                    |skn: &SenderKeyName| { Ok(skn.sender()?.name().to_string()) });

ffi_fn_get_uint32!(signal_sender_key_name_get_sender_device_id(SenderKeyName) using
                   |m: &SenderKeyName| Ok(m.sender()?.device_id()));

#[no_mangle]
pub unsafe extern "C" fn signal_sender_key_record_new_fresh(
    obj: *mut *mut SenderKeyRecord,
) -> *mut SignalFfiError {
    run_ffi_safe(|| box_object::<SenderKeyRecord>(obj, Ok(SenderKeyRecord::new_empty())))
}

ffi_fn_clone!(signal_sender_key_record_clone clones SenderKeyRecord);

ffi_fn_destroy!(signal_sender_key_record_destroy destroys SenderKeyRecord);

ffi_fn_deserialize!(signal_sender_key_record_deserialize(SenderKeyRecord) is SenderKeyRecord::deserialize);

ffi_fn_get_bytearray!(signal_sender_key_record_serialize(SenderKeyRecord) using
                      |sks: &SenderKeyRecord| sks.serialize());

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

#[async_trait(?Send)]
impl IdentityKeyStore for FfiIdentityKeyStore {
    async fn get_identity_key_pair(
        &self,
        ctx: Context,
    ) -> Result<IdentityKeyPair, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut key = std::ptr::null_mut();
        let result = (self.store.get_identity_key_pair)(self.store.ctx, &mut key, ctx);

        if result != 0 {
            return Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "get_identity_key_pair",
                    result,
                ),
            );
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

        if result != 0 {
            return Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "get_local_registration_id",
                    result,
                ),
            );
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
            r => Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError("save_identity", r),
            ),
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
            r => Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "is_trusted_identity",
                    r,
                ),
            ),
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

        if result != 0 {
            return Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "get_identity",
                    result,
                ),
            );
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

        if result != 0 {
            return Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "load_pre_key",
                    result,
                ),
            );
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

        if result != 0 {
            return Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "store_pre_key",
                    result,
                ),
            );
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

        if result != 0 {
            return Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "remove_pre_key",
                    result,
                ),
            );
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

        if result != 0 {
            return Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "load_signed_pre_key",
                    result,
                ),
            );
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

        if result != 0 {
            return Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "store_signed_pre_key",
                    result,
                ),
            );
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

        if result != 0 {
            return Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "load_session",
                    result,
                ),
            );
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

        if result != 0 {
            return Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "store_session",
                    result,
                ),
            );
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

ffi_fn_destroy!(signal_ciphertext_message_destroy destroys CiphertextMessage);

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
        write_bytearray_to(result, result_len, Ok(bits))
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
        ));
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
        ));

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

        if result != 0 {
            return Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "store_sender_key",
                    result,
                ),
            );
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

        if result != 0 {
            return Err(
                SignalProtocolError::ApplicationCallbackReturnedIntegerError(
                    "load_sender_key",
                    result,
                ),
            );
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
        ));
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
        ));
        write_bytearray_to(out, out_len, ptext)
    })
}

// Server Certificate
ffi_fn_deserialize!(signal_server_certificate_deserialize(ServerCertificate) is ServerCertificate::deserialize);

ffi_fn_destroy!(signal_server_certificate_destroy destroys ServerCertificate);

ffi_fn_get_uint32!(signal_server_certificate_get_key_id(ServerCertificate) using ServerCertificate::key_id);

ffi_fn_get_bytearray!(signal_server_certificate_get_serialized(ServerCertificate) using ServerCertificate::serialized);
ffi_fn_get_bytearray!(signal_server_certificate_get_certificate(ServerCertificate) using ServerCertificate::certificate);
ffi_fn_get_bytearray!(signal_server_certificate_get_signature(ServerCertificate) using ServerCertificate::signature);

ffi_fn_get_new_boxed_obj!(signal_server_certificate_get_key(PublicKey) from ServerCertificate,
                          ServerCertificate::public_key);

#[no_mangle]
pub unsafe extern "C" fn signal_server_certificate_new(
    out: *mut *mut ServerCertificate,
    key_id: c_uint,
    server_key: *const PublicKey,
    trust_root: *const PrivateKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let server_key = native_handle_cast::<PublicKey>(server_key)?;
        let trust_root = native_handle_cast::<PrivateKey>(trust_root)?;
        let mut rng = rand::rngs::OsRng;

        let sc = ServerCertificate::new(key_id, *server_key, trust_root, &mut rng);
        box_object(out, sc)
    })
}

// Sender Certificate
ffi_fn_destroy!(signal_sender_certificate_destroy destroys SenderCertificate);
ffi_fn_deserialize!(signal_sender_certificate_deserialize(SenderCertificate) is SenderCertificate::deserialize);

ffi_fn_get_uint64!(signal_sender_certificate_get_expiration(SenderCertificate) using SenderCertificate::expiration);
ffi_fn_get_uint32!(signal_sender_certificate_get_device_id(SenderCertificate) using SenderCertificate::sender_device_id);

ffi_fn_get_bytearray!(signal_sender_certificate_get_serialized(SenderCertificate) using SenderCertificate::serialized);
ffi_fn_get_bytearray!(signal_sender_certificate_get_certificate(SenderCertificate) using SenderCertificate::certificate);
ffi_fn_get_bytearray!(signal_sender_certificate_get_signature(SenderCertificate) using SenderCertificate::signature);

ffi_fn_get_new_boxed_obj!(signal_sender_certificate_get_key(PublicKey) from SenderCertificate,
                          SenderCertificate::key);
ffi_fn_get_new_boxed_obj!(signal_sender_certificate_get_server_certificate(ServerCertificate) from SenderCertificate,
                          |s: &SenderCertificate| Ok(s.signer()?.clone()));

ffi_fn_get_optional_cstring!(signal_sender_certificate_get_sender_uuid(SenderCertificate) using
                             |s: &SenderCertificate| Ok(s.sender_uuid()?.map(|s| s.to_string())));
ffi_fn_get_optional_cstring!(signal_sender_certificate_get_sender_e164(SenderCertificate) using
                             |s: &SenderCertificate| Ok(s.sender_e164()?.map(|s| s.to_string())));

#[no_mangle]
pub unsafe extern "C" fn signal_sender_certificate_preferred_address(
    obj: *mut *mut ProtocolAddress,
    cert: *const SenderCertificate,
    session_store: *const FfiSessionStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let cert = native_handle_cast::<SenderCertificate>(cert)?;
        let session_store = FfiSessionStore::new(session_store)?;
        let address = expect_ready(cert.preferred_address(&session_store, Some(ctx)))?;
        box_object::<ProtocolAddress>(obj, Ok(address))
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_sender_certificate_validate(
    valid: *mut bool,
    cert: *const SenderCertificate,
    key: *const PublicKey,
    time: u64,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let cert = native_handle_cast::<SenderCertificate>(cert)?;
        let key = native_handle_cast::<PublicKey>(key)?;
        *valid = cert.validate(key, time)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_sender_certificate_new(
    out: *mut *mut SenderCertificate,
    sender_uuid: *const c_char,
    sender_e164: *const c_char,
    sender_device_id: u32,
    sender_key: *const PublicKey,
    expiration: u64,
    signer_cert: *const ServerCertificate,
    signer_key: *const PrivateKey,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let sender_uuid = read_optional_c_string(sender_uuid)?;
        let sender_e164 = read_optional_c_string(sender_e164)?;
        let sender_key = native_handle_cast::<PublicKey>(sender_key)?;
        let signer_cert = native_handle_cast::<ServerCertificate>(signer_cert)?;
        let signer_key = native_handle_cast::<PrivateKey>(signer_key)?;

        let mut rng = rand::rngs::OsRng;

        let sc = SenderCertificate::new(
            sender_uuid,
            sender_e164,
            *sender_key,
            sender_device_id,
            expiration,
            signer_cert.clone(),
            signer_key,
            &mut rng,
        );
        box_object(out, sc)
    })
}

// UnidentifiedSenderMessageContent
ffi_fn_destroy!(signal_unidentified_sender_message_content_destroy destroys UnidentifiedSenderMessageContent);
ffi_fn_deserialize!(signal_unidentified_sender_message_content_deserialize(UnidentifiedSenderMessageContent) is UnidentifiedSenderMessageContent::deserialize);

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

ffi_fn_get_bytearray!(signal_unidentified_sender_message_content_get_serialized(UnidentifiedSenderMessageContent) using UnidentifiedSenderMessageContent::serialized);
ffi_fn_get_bytearray!(signal_unidentified_sender_message_content_get_contents(UnidentifiedSenderMessageContent) using UnidentifiedSenderMessageContent::contents);

ffi_fn_get_new_boxed_obj!(signal_unidentified_sender_message_content_get_sender_cert(SenderCertificate) from UnidentifiedSenderMessageContent,
                          |s: &UnidentifiedSenderMessageContent| Ok(s.sender()?.clone()));

#[no_mangle]
pub unsafe extern "C" fn signal_unidentified_sender_message_content_new(
    obj: *mut *mut UnidentifiedSenderMessageContent,
    msg_type: c_uint,
    sender: *const SenderCertificate,
    contents: *const c_uchar,
    contents_len: size_t,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let sender = native_handle_cast::<SenderCertificate>(sender)?;
        let contents = as_slice(contents, contents_len)?;

        // This encoding is from the protobufs
        let msg_type = match msg_type {
            1 => Ok(CiphertextMessageType::PreKey),
            2 => Ok(CiphertextMessageType::Whisper),
            x => Err(SignalFfiError::Signal(
                SignalProtocolError::InvalidArgument(format!("invalid msg_type argument {}", x)),
            )),
        }?;

        let usmc =
            UnidentifiedSenderMessageContent::new(msg_type, sender.clone(), contents.to_vec())?;
        box_object::<UnidentifiedSenderMessageContent>(obj, Ok(usmc))
    })
}

// UnidentifiedSenderMessage
ffi_fn_destroy!(signal_unidentified_sender_message_destroy destroys UnidentifiedSenderMessage);
ffi_fn_deserialize!(signal_unidentified_sender_message_deserialize(UnidentifiedSenderMessage) is UnidentifiedSenderMessage::deserialize);

ffi_fn_get_bytearray!(signal_unidentified_sender_message_get_serialized(UnidentifiedSenderMessage) using UnidentifiedSenderMessage::serialized);
ffi_fn_get_bytearray!(signal_unidentified_sender_message_get_encrypted_message(UnidentifiedSenderMessage) using UnidentifiedSenderMessage::encrypted_message);
ffi_fn_get_bytearray!(signal_unidentified_sender_message_get_encrypted_static(UnidentifiedSenderMessage) using UnidentifiedSenderMessage::encrypted_static);

ffi_fn_get_new_boxed_obj!(signal_unidentified_sender_message_get_ephemeral_public(PublicKey) from UnidentifiedSenderMessage,
                          UnidentifiedSenderMessage::ephemeral_public);

#[no_mangle]
pub unsafe extern "C" fn signal_unidentified_sender_message_new(
    obj: *mut *mut UnidentifiedSenderMessage,
    public_key: *const PublicKey,
    encrypted_static: *const c_uchar,
    encrypted_static_len: size_t,
    encrypted_message: *const c_uchar,
    encrypted_message_len: size_t,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let encrypted_static = as_slice(encrypted_static, encrypted_static_len)?;
        let encrypted_message = as_slice(encrypted_message, encrypted_message_len)?;
        let public_key = native_handle_cast::<PublicKey>(public_key)?;

        let usm = UnidentifiedSenderMessage::new(
            *public_key,
            encrypted_static.to_vec(),
            encrypted_message.to_vec(),
        )?;
        box_object::<UnidentifiedSenderMessage>(obj, Ok(usm))
    })
}

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
        write_bytearray_to(out, out_len, Ok(ctext))
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_sealed_session_cipher_decrypt_to_usmc(
    out: *mut *mut UnidentifiedSenderMessageContent,
    ctext: *const c_uchar,
    ctext_len: size_t,
    trust_root: *const PublicKey,
    timestamp: u64,
    identity_store: *const FfiIdentityKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let ctext = as_slice(ctext, ctext_len)?;
        let trust_root = native_handle_cast::<PublicKey>(trust_root)?;
        let mut identity_store = FfiIdentityKeyStore::new(identity_store)?;

        let usmc = expect_ready(sealed_sender_decrypt_to_usmc(
            ctext,
            trust_root,
            timestamp,
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
        write_bytearray_to(out, out_len, Ok(decrypted.message))
    })
}
