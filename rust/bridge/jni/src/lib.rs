//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(warnings)]

use async_trait::async_trait;
use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jobject, jstring};
use jni::JNIEnv;
use libsignal_protocol_rust::*;
use std::convert::TryFrom;

mod util;

use crate::util::*;

type JavaSessionStore = jobject;
type JavaIdentityKeyStore = jobject;
type JavaPreKeyStore = jobject;
type JavaSignedPreKeyStore = jobject;
type JavaCiphertextMessage = jobject;
type JavaSenderKeyStore = jobject;

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_ProtocolAddress_1New(
    env: JNIEnv,
    _class: JClass,
    name: JString,
    device_id: jint,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let name: String = env.get_string(name)?.into();
        let device_id = jint_to_u32(device_id)?;
        let address = ProtocolAddress::new(name, device_id);
        box_object::<ProtocolAddress>(Ok(address))
    })
}

jni_fn_destroy!(Java_org_signal_client_internal_Native_ProtocolAddress_1Destroy destroys ProtocolAddress);

jni_fn_get_jstring!(Java_org_signal_client_internal_Native_ProtocolAddress_1Name(ProtocolAddress) using
                    |p: &ProtocolAddress| Ok(p.name().to_string()));

jni_fn_get_jint!(Java_org_signal_client_internal_Native_ProtocolAddress_1DeviceId(ProtocolAddress) using
                 |obj: &ProtocolAddress| { Ok(obj.device_id()) });

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_ECPublicKey_1Deserialize(
    env: JNIEnv,
    _class: JClass,
    data: jbyteArray,
    offset: jint,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let offset = jint_to_u32(offset)? as usize;
        let data = env.convert_byte_array(data)?;
        let key = PublicKey::deserialize(&data[offset..])?;
        box_object::<PublicKey>(Ok(key))
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_ECPublicKey_1Compare(
    env: JNIEnv,
    _class: JClass,
    key1: ObjectHandle,
    key2: ObjectHandle,
) -> jint {
    run_ffi_safe(&env, || {
        let key1 = native_handle_cast::<PublicKey>(key1)?;
        let key2 = native_handle_cast::<PublicKey>(key2)?;

        match key1.cmp(&key2) {
            std::cmp::Ordering::Less => Ok(-1),
            std::cmp::Ordering::Equal => Ok(0),
            std::cmp::Ordering::Greater => Ok(1),
        }
    })
}

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_ECPublicKey_1Serialize(PublicKey) using
                       |k: &PublicKey| Ok(k.serialize()));

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_ECPublicKey_1GetPublicKeyBytes(PublicKey) using
                       PublicKey::public_key_bytes);

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_ECPublicKey_1Verify(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
    message: jbyteArray,
    signature: jbyteArray,
) -> jboolean {
    run_ffi_safe(&env, || {
        let key = native_handle_cast::<PublicKey>(handle)?;
        let message = env.convert_byte_array(message)?;
        let signature = env.convert_byte_array(signature)?;
        Ok(key.verify_signature(&message, &signature)? as jboolean)
    })
}

jni_fn_destroy!(Java_org_signal_client_internal_Native_ECPublicKey_1Destroy destroys PublicKey);

jni_fn_deserialize!(Java_org_signal_client_internal_Native_ECPrivateKey_1Deserialize is PrivateKey::deserialize);

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_ECPrivateKey_1Serialize(PrivateKey) using
                       |k: &PrivateKey| Ok(k.serialize()));

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_ECPrivateKey_1Generate(
    env: JNIEnv,
    _class: JClass,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let mut rng = rand::rngs::OsRng;
        let keypair = KeyPair::generate(&mut rng);
        box_object::<PrivateKey>(Ok(keypair.private_key))
    })
}

jni_fn_get_new_boxed_obj!(Java_org_signal_client_internal_Native_ECPrivateKey_1GetPublicKey(PublicKey) from PrivateKey,
                          PrivateKey::public_key);

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_ECPrivateKey_1Sign(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
    message: jbyteArray,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let message = env.convert_byte_array(message)?;
        let key = native_handle_cast::<PrivateKey>(handle)?;
        let mut rng = rand::rngs::OsRng;
        let sig = key.calculate_signature(&message, &mut rng)?;
        to_jbytearray(&env, Ok(sig))
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_ECPrivateKey_1Agree(
    env: JNIEnv,
    _class: JClass,
    private_key_handle: ObjectHandle,
    public_key_handle: ObjectHandle,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let private_key = native_handle_cast::<PrivateKey>(private_key_handle)?;
        let public_key = native_handle_cast::<PublicKey>(public_key_handle)?;
        let shared_secret = private_key.calculate_agreement(&public_key)?;
        to_jbytearray(&env, Ok(shared_secret))
    })
}

jni_fn_destroy!(Java_org_signal_client_internal_Native_ECPrivateKey_1Destroy destroys PrivateKey);

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_IdentityKeyPair_1Serialize(
    env: JNIEnv,
    _class: JClass,
    public_key_handle: ObjectHandle,
    private_key_handle: ObjectHandle,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let public_key = native_handle_cast::<PublicKey>(public_key_handle)?;
        let private_key = native_handle_cast::<PrivateKey>(private_key_handle)?;
        let identity_key = IdentityKey::new(*public_key);
        let identity_key_pair = IdentityKeyPair::new(identity_key, *private_key);
        to_jbytearray(&env, Ok(identity_key_pair.serialize()))
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_DisplayableFingerprint_1Format(
    env: JNIEnv,
    _class: JClass,
    local: jbyteArray,
    remote: jbyteArray,
) -> jstring {
    run_ffi_safe(&env, || {
        let local = env.convert_byte_array(local)?;
        let remote = env.convert_byte_array(remote)?;
        let fingerprint = DisplayableFingerprint::new(&local, &remote)?;
        let result = env.new_string(format!("{}", fingerprint))?;
        Ok(result.into_inner())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_NumericFingerprintGenerator_1New(
    env: JNIEnv,
    _class: JClass,
    iterations: jint,
    version: jint,
    local_identifier: jbyteArray,
    local_key: jbyteArray,
    remote_identifier: jbyteArray,
    remote_key: jbyteArray,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let version = jint_to_u32(version)?;
        let iterations = jint_to_u32(iterations)?;

        let local_identifier = env.convert_byte_array(local_identifier)?;
        let local_key = env.convert_byte_array(local_key)?;

        let remote_identifier = env.convert_byte_array(remote_identifier)?;
        let remote_key = env.convert_byte_array(remote_key)?;

        let local_key = IdentityKey::decode(&local_key)?;
        let remote_key = IdentityKey::decode(&remote_key)?;
        let fprint = Fingerprint::new(
            version,
            iterations,
            &local_identifier,
            &local_key,
            &remote_identifier,
            &remote_key,
        )?;

        box_object::<Fingerprint>(Ok(fprint))
    })
}

jni_fn_destroy!(Java_org_signal_client_internal_Native_NumericFingerprintGenerator_1Destroy destroys Fingerprint);

jni_fn_get_jstring!(Java_org_signal_client_internal_Native_NumericFingerprintGenerator_1GetDisplayString(Fingerprint) using
    Fingerprint::display_string);

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_NumericFingerprintGenerator_1GetScannableEncoding(Fingerprint) using
                       |f: &Fingerprint| f.scannable.serialize());

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_ScannableFingerprint_1Compare(
    env: JNIEnv,
    _class: JClass,
    fprint1: jbyteArray,
    fprint2: jbyteArray,
) -> jboolean {
    run_ffi_safe(&env, || {
        let fprint1 = env.convert_byte_array(fprint1)?;
        let fprint2 = env.convert_byte_array(fprint2)?;

        let fprint1 = ScannableFingerprint::deserialize(&fprint1)?;
        Ok(fprint1.compare(&fprint2)? as jboolean)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_HKDF_1DeriveSecrets(
    env: JNIEnv,
    _class: JClass,
    version: jint,
    input_key_material: jbyteArray,
    salt: jbyteArray,
    info: jbyteArray,
    output_length: jint,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let version = jint_to_u32(version)?;
        let output_length = output_length as usize;

        let input_key_material = env.convert_byte_array(input_key_material)?;

        let salt = if salt.is_null() {
            None
        } else {
            Some(env.convert_byte_array(salt)?)
        };

        let info = if info.is_null() {
            vec![]
        } else {
            env.convert_byte_array(info)?
        };

        let hkdf = HKDF::new(version)?;
        let derived = if let Some(salt) = salt {
            hkdf.derive_salted_secrets(&input_key_material, &salt, &info, output_length)
        } else {
            hkdf.derive_secrets(&input_key_material, &info, output_length)
        };

        to_jbytearray(&env, derived)
    })
}

jni_fn_deserialize!(Java_org_signal_client_internal_Native_SignalMessage_1Deserialize is SignalMessage::try_from);

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SignalMessage_1New(
    env: JNIEnv,
    _class: JClass,
    message_version: jint,
    mac_key: jbyteArray,
    sender_ratchet_key: ObjectHandle,
    counter: jint,
    previous_counter: jint,
    ciphertext: jbyteArray,
    sender_identity_key: ObjectHandle,
    receiver_identity_key: ObjectHandle,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let message_version = jint_to_u8(message_version)?;
        let mac_key = env.convert_byte_array(mac_key)?;
        let sender_ratchet_key = native_handle_cast::<PublicKey>(sender_ratchet_key)?;
        let counter = jint_to_u32(counter)?;
        let previous_counter = jint_to_u32(previous_counter)?;
        let ciphertext = env.convert_byte_array(ciphertext)?;

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
        )?;

        box_object::<SignalMessage>(Ok(msg))
    })
}

jni_fn_destroy!(Java_org_signal_client_internal_Native_SignalMessage_1Destroy destroys SignalMessage);

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_SignalMessage_1GetSenderRatchetKey(SignalMessage) using
                       |m: &SignalMessage| Ok(m.sender_ratchet_key().serialize()));

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_SignalMessage_1GetBody(SignalMessage) using
                       |m: &SignalMessage| Ok(m.body().to_vec()));
jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_SignalMessage_1GetSerialized(SignalMessage) using
                       |m: &SignalMessage| Ok(m.serialized().to_vec()));

jni_fn_get_jint!(Java_org_signal_client_internal_Native_SignalMessage_1GetMessageVersion(SignalMessage) using
                 |msg: &SignalMessage| { Ok(msg.message_version() as u32) });

jni_fn_get_jint!(Java_org_signal_client_internal_Native_SignalMessage_1GetCounter(SignalMessage) using
                 |msg: &SignalMessage| { Ok(msg.counter()) });

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SignalMessage_1VerifyMac(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
    sender_identity_key: ObjectHandle,
    receiver_identity_key: ObjectHandle,
    mac_key: jbyteArray,
) -> jboolean {
    run_ffi_safe(&env, || {
        let msg = native_handle_cast::<SignalMessage>(handle)?;
        let sender_identity_key = native_handle_cast::<PublicKey>(sender_identity_key)?;
        let receiver_identity_key = native_handle_cast::<PublicKey>(receiver_identity_key)?;
        let mac_key = env.convert_byte_array(mac_key)?;

        let valid = msg.verify_mac(
            &IdentityKey::new(*sender_identity_key),
            &IdentityKey::new(*receiver_identity_key),
            &mac_key,
        )?;

        Ok(valid as jboolean)
    })
}

jni_fn_deserialize!(Java_org_signal_client_internal_Native_PreKeySignalMessage_1Deserialize is PreKeySignalMessage::try_from);

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_PreKeySignalMessage_1New(
    env: JNIEnv,
    _class: JClass,
    message_version: jint,
    registration_id: jint,
    pre_key_id: jint,
    signed_pre_key_id: jint,
    base_key_handle: ObjectHandle,
    identity_key_handle: ObjectHandle,
    signal_message_handle: ObjectHandle,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let message_version = message_version as u8;
        let registration_id = jint_to_u32(registration_id)?;
        let pre_key_id = if pre_key_id < 0 {
            None
        } else {
            Some(jint_to_u32(pre_key_id)?)
        };
        let signed_pre_key_id = jint_to_u32(signed_pre_key_id)?;
        let base_key = native_handle_cast::<PublicKey>(base_key_handle)?;
        let identity_key = native_handle_cast::<PublicKey>(identity_key_handle)?;
        let signal_message = native_handle_cast::<SignalMessage>(signal_message_handle)?;

        let msg = PreKeySignalMessage::new(
            message_version,
            registration_id,
            pre_key_id,
            signed_pre_key_id,
            *base_key,
            IdentityKey::new(*identity_key),
            signal_message.clone(),
        );
        box_object::<PreKeySignalMessage>(msg)
    })
}

jni_fn_destroy!(Java_org_signal_client_internal_Native_PreKeySignalMessage_1Destroy destroys PreKeySignalMessage);

jni_fn_get_jint!(Java_org_signal_client_internal_Native_PreKeySignalMessage_1GetVersion(PreKeySignalMessage) using
                 |m: &PreKeySignalMessage| Ok(m.message_version() as u32));

jni_fn_get_jint!(Java_org_signal_client_internal_Native_PreKeySignalMessage_1GetRegistrationId(PreKeySignalMessage) using
                 |m: &PreKeySignalMessage| Ok(m.registration_id()));

// Special logic to handle optionality:
#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_PreKeySignalMessage_1GetPreKeyId(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
) -> jint {
    run_ffi_safe(&env, || {
        let pksm = native_handle_cast::<PreKeySignalMessage>(handle)?;
        match pksm.pre_key_id() {
            Some(id) => jint_from_u32(Ok(id)),
            None => Ok(-1),
        }
    })
}

jni_fn_get_jint!(Java_org_signal_client_internal_Native_PreKeySignalMessage_1GetSignedPreKeyId(PreKeySignalMessage) using
                 |m: &PreKeySignalMessage| Ok(m.signed_pre_key_id()));

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_PreKeySignalMessage_1GetBaseKey(PreKeySignalMessage) using
                       |m: &PreKeySignalMessage| Ok(m.base_key().serialize()));

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_PreKeySignalMessage_1GetIdentityKey(PreKeySignalMessage) using
                       |m: &PreKeySignalMessage| Ok(m.identity_key().serialize()));

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_PreKeySignalMessage_1GetSignalMessage(PreKeySignalMessage) using
                       |m: &PreKeySignalMessage| Ok(m.message().serialized().to_vec()));

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_PreKeySignalMessage_1GetSerialized(PreKeySignalMessage) using
                       |m: &PreKeySignalMessage| Ok(m.serialized().to_vec()));

jni_fn_deserialize!(Java_org_signal_client_internal_Native_SenderKeyMessage_1Deserialize is SenderKeyMessage::try_from);

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SenderKeyMessage_1New(
    env: JNIEnv,
    _class: JClass,
    key_id: jint,
    iteration: jint,
    ciphertext: jbyteArray,
    pk_handle: ObjectHandle,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let key_id = jint_to_u32(key_id)?;
        let iteration = jint_to_u32(iteration)?;
        let ciphertext = env.convert_byte_array(ciphertext)?;
        let signature_key = native_handle_cast::<PrivateKey>(pk_handle)?;
        let mut csprng = rand::rngs::OsRng;
        let skm = SenderKeyMessage::new(key_id, iteration, &ciphertext, &mut csprng, signature_key);
        box_object::<SenderKeyMessage>(skm)
    })
}

jni_fn_deserialize!(Java_org_signal_client_internal_Native_SenderKeyDistributionMessage_1Deserialize is SenderKeyDistributionMessage::try_from);

jni_fn_destroy!(Java_org_signal_client_internal_Native_SenderKeyMessage_1Destroy destroys SenderKeyMessage);

jni_fn_get_jint!(Java_org_signal_client_internal_Native_SenderKeyMessage_1GetKeyId(SenderKeyMessage) using
                 |m: &SenderKeyMessage| Ok(m.key_id()));

jni_fn_get_jint!(Java_org_signal_client_internal_Native_SenderKeyMessage_1GetIteration(SenderKeyMessage) using
                 |m: &SenderKeyMessage| Ok(m.iteration()));

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_SenderKeyMessage_1GetCipherText(SenderKeyMessage) using
                       |m: &SenderKeyMessage| Ok(m.ciphertext().to_vec()));

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_SenderKeyMessage_1GetSerialized(SenderKeyMessage) using
                       |m: &SenderKeyMessage| Ok(m.serialized().to_vec()));

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SenderKeyMessage_1VerifySignature(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
    pubkey_handle: ObjectHandle,
) -> jboolean {
    run_ffi_safe(&env, || {
        let skm = native_handle_cast::<SenderKeyMessage>(handle)?;
        let pubkey = native_handle_cast::<PublicKey>(pubkey_handle)?;
        let valid = skm.verify_signature(pubkey)?;
        Ok(valid as jboolean)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SenderKeyDistributionMessage_1New(
    env: JNIEnv,
    _class: JClass,
    key_id: jint,
    iteration: jint,
    chainkey: jbyteArray,
    pk_handle: ObjectHandle,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let key_id = jint_to_u32(key_id)?;
        let iteration = jint_to_u32(iteration)?;
        let chainkey = env.convert_byte_array(chainkey)?;
        let signature_key = native_handle_cast::<PublicKey>(pk_handle)?;
        let skdm = SenderKeyDistributionMessage::new(key_id, iteration, &chainkey, *signature_key);
        box_object::<SenderKeyDistributionMessage>(skdm)
    })
}

jni_fn_destroy!(Java_org_signal_client_internal_Native_SenderKeyDistributionMessage_1Destroy destroys SenderKeyDistributionMessage);

jni_fn_get_jint!(Java_org_signal_client_internal_Native_SenderKeyDistributionMessage_1GetId(SenderKeyDistributionMessage) using
                 SenderKeyDistributionMessage::id);

jni_fn_get_jint!(Java_org_signal_client_internal_Native_SenderKeyDistributionMessage_1GetIteration(SenderKeyDistributionMessage) using
                 SenderKeyDistributionMessage::iteration);

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_SenderKeyDistributionMessage_1GetChainKey(SenderKeyDistributionMessage) using
                       |m: &SenderKeyDistributionMessage| Ok(m.chain_key()?.to_vec()));

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_SenderKeyDistributionMessage_1GetSignatureKey(SenderKeyDistributionMessage) using
                       |m: &SenderKeyDistributionMessage| Ok(m.signing_key()?.serialize()));

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_SenderKeyDistributionMessage_1GetSerialized(SenderKeyDistributionMessage) using
                       |m: &SenderKeyDistributionMessage| Ok(m.serialized().to_vec()));

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_PreKeyBundle_1New(
    env: JNIEnv,
    _class: JClass,
    registration_id: jint,
    device_id: jint,
    prekey_id: jint,
    prekey_handle: ObjectHandle,
    signed_prekey_id: jint,
    signed_prekey_handle: ObjectHandle,
    signed_prekey_signature: jbyteArray,
    identity_key_handle: ObjectHandle,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let registration_id = jint_to_u32(registration_id)?;
        let device_id = jint_to_u32(device_id)?;
        let signed_prekey_id = jint_to_u32(signed_prekey_id)?;
        let signed_prekey = native_handle_cast::<PublicKey>(signed_prekey_handle)?;
        let signed_prekey_signature = env.convert_byte_array(signed_prekey_signature)?;

        let prekey = native_handle_cast_optional::<PublicKey>(prekey_handle)?.map(|k| *k);

        let prekey_id = if prekey_id < 0 {
            None
        } else {
            Some(jint_to_u32(prekey_id)?)
        };

        let identity_key = IdentityKey::new(*(identity_key_handle as *mut PublicKey));

        let bundle = PreKeyBundle::new(
            registration_id,
            device_id,
            prekey_id,
            prekey,
            signed_prekey_id,
            *signed_prekey,
            signed_prekey_signature,
            identity_key,
        );

        box_object::<PreKeyBundle>(bundle)
    })
}

jni_fn_destroy!(Java_org_signal_client_internal_Native_PreKeyBundle_1Destroy destroys PreKeyBundle);

jni_fn_get_jint!(Java_org_signal_client_internal_Native_PreKeyBundle_1GetRegistrationId(PreKeyBundle) using
                 PreKeyBundle::registration_id);

jni_fn_get_jint!(Java_org_signal_client_internal_Native_PreKeyBundle_1GetDeviceId(PreKeyBundle) using
                 PreKeyBundle::device_id);

jni_fn_get_jint!(Java_org_signal_client_internal_Native_PreKeyBundle_1GetSignedPreKeyId(PreKeyBundle) using
                 PreKeyBundle::signed_pre_key_id);

// Special logic for optional here:
#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_PreKeyBundle_1GetPreKeyId(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
) -> jint {
    run_ffi_safe(&env, || {
        let bundle = native_handle_cast::<PreKeyBundle>(handle)?;
        match bundle.pre_key_id()? {
            Some(prekey_id) => jint_from_u32(Ok(prekey_id)),
            None => Ok(-1),
        }
    })
}

jni_fn_get_new_boxed_optional_obj!(Java_org_signal_client_internal_Native_PreKeyBundle_1GetPreKeyPublic(PublicKey) from PreKeyBundle,
                                   PreKeyBundle::pre_key_public);

jni_fn_get_new_boxed_obj!(Java_org_signal_client_internal_Native_PreKeyBundle_1GetSignedPreKeyPublic(PublicKey) from PreKeyBundle,
                          |p: &PreKeyBundle| Ok(p.signed_pre_key_public()?));

jni_fn_get_new_boxed_obj!(Java_org_signal_client_internal_Native_PreKeyBundle_1GetIdentityKey(PublicKey) from PreKeyBundle,
                          |p: &PreKeyBundle| Ok(*p.identity_key()?.public_key()));

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_PreKeyBundle_1GetSignedPreKeySignature(PreKeyBundle) using
                       |m: &PreKeyBundle| Ok(m.signed_pre_key_signature()?.to_vec()));

/* SignedPreKeyRecord */

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SignedPreKeyRecord_1New(
    env: JNIEnv,
    _class: JClass,
    id: jint,
    timestamp: jlong,
    pub_key_handle: ObjectHandle,
    priv_key_handle: ObjectHandle,
    signature: jbyteArray,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let pub_key = native_handle_cast::<PublicKey>(pub_key_handle)?;
        let priv_key = native_handle_cast::<PrivateKey>(priv_key_handle)?;
        let id = jint_to_u32(id)?;
        let timestamp = timestamp as u64;
        let keypair = KeyPair::new(*pub_key, *priv_key);
        let signature = env.convert_byte_array(signature)?;

        let spkr = SignedPreKeyRecord::new(id, timestamp, &keypair, &signature);

        box_object::<SignedPreKeyRecord>(Ok(spkr))
    })
}

jni_fn_deserialize!(Java_org_signal_client_internal_Native_SignedPreKeyRecord_1Deserialize is SignedPreKeyRecord::deserialize);

jni_fn_get_jint!(Java_org_signal_client_internal_Native_SignedPreKeyRecord_1GetId(SignedPreKeyRecord) using
                 SignedPreKeyRecord::id);

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SignedPreKeyRecord_1GetTimestamp(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
) -> jlong {
    run_ffi_safe(&env, || {
        let spkr = native_handle_cast::<SignedPreKeyRecord>(handle)?;
        jlong_from_u64(spkr.timestamp())
    })
}

jni_fn_get_new_boxed_obj!(Java_org_signal_client_internal_Native_SignedPreKeyRecord_1GetPublicKey(PublicKey) from SignedPreKeyRecord,
                          SignedPreKeyRecord::public_key);

jni_fn_get_new_boxed_obj!(Java_org_signal_client_internal_Native_SignedPreKeyRecord_1GetPrivateKey(PrivateKey) from SignedPreKeyRecord,
                          SignedPreKeyRecord::private_key);

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_SignedPreKeyRecord_1GetSignature(SignedPreKeyRecord) using
                       SignedPreKeyRecord::signature);

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_SignedPreKeyRecord_1GetSerialized(SignedPreKeyRecord) using
                       SignedPreKeyRecord::serialize);

jni_fn_destroy!(Java_org_signal_client_internal_Native_SignedPreKeyRecord_1Destroy destroys SignedPreKeyRecord);

/* PreKeyRecord */

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_PreKeyRecord_1New(
    env: JNIEnv,
    _class: JClass,
    id: jint,
    pub_key_handle: ObjectHandle,
    priv_key_handle: ObjectHandle,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let id = jint_to_u32(id)?;
        let pub_key = native_handle_cast::<PublicKey>(pub_key_handle)?;
        let priv_key = native_handle_cast::<PrivateKey>(priv_key_handle)?;
        let keypair = KeyPair::new(*pub_key, *priv_key);

        let pkr = PreKeyRecord::new(id, &keypair);

        box_object::<PreKeyRecord>(Ok(pkr))
    })
}

jni_fn_deserialize!(Java_org_signal_client_internal_Native_PreKeyRecord_1Deserialize is PreKeyRecord::deserialize);

jni_fn_get_jint!(Java_org_signal_client_internal_Native_PreKeyRecord_1GetId(PreKeyRecord) using
                 PreKeyRecord::id);

jni_fn_get_new_boxed_obj!(Java_org_signal_client_internal_Native_PreKeyRecord_1GetPublicKey(PublicKey) from PreKeyRecord,
                          PreKeyRecord::public_key);

jni_fn_get_new_boxed_obj!(Java_org_signal_client_internal_Native_PreKeyRecord_1GetPrivateKey(PrivateKey) from PreKeyRecord,
                          PreKeyRecord::private_key);

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_PreKeyRecord_1GetSerialized(PreKeyRecord) using
                       PreKeyRecord::serialize);

jni_fn_destroy!(Java_org_signal_client_internal_Native_PreKeyRecord_1Destroy destroys PreKeyRecord);

/* SenderKeyName */

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SenderKeyName_1New(
    env: JNIEnv,
    _class: JClass,
    group_id: JString,
    sender_name: JString,
    sender_device_id: jint,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let group_id: String = env.get_string(group_id)?.into();
        let sender_name = env.get_string(sender_name)?.into();
        let sender_id = jint_to_u32(sender_device_id)?;
        let name = SenderKeyName::new(group_id, ProtocolAddress::new(sender_name, sender_id));
        box_object::<SenderKeyName>(name)
    })
}

jni_fn_destroy!(Java_org_signal_client_internal_Native_SenderKeyName_1Destroy destroys SenderKeyName);

jni_fn_get_jstring!(Java_org_signal_client_internal_Native_SenderKeyName_1GetGroupId(SenderKeyName) using
                    SenderKeyName::group_id);

jni_fn_get_jstring!(Java_org_signal_client_internal_Native_SenderKeyName_1GetSenderName(SenderKeyName) using
                    |skn: &SenderKeyName| { Ok(skn.sender()?.name().to_string()) });

jni_fn_get_jint!(Java_org_signal_client_internal_Native_SenderKeyName_1GetSenderDeviceId(SenderKeyName) using
                 |m: &SenderKeyName| Ok(m.sender()?.device_id()));

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SenderKeyRecord_1New(
    env: JNIEnv,
    _class: JClass,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let skr = SenderKeyRecord::new_empty();
        box_object::<SenderKeyRecord>(Ok(skr))
    })
}

jni_fn_destroy!(Java_org_signal_client_internal_Native_SenderKeyRecord_1Destroy destroys SenderKeyRecord);

jni_fn_deserialize!(Java_org_signal_client_internal_Native_SenderKeyRecord_1Deserialize is SenderKeyRecord::deserialize);

jni_fn_get_jbytearray!(Java_org_signal_client_internal_Native_SenderKeyRecord_1GetSerialized(SenderKeyRecord) using
                       SenderKeyRecord::serialize);

fn sender_key_name_to_jobject<'a>(
    env: &'a JNIEnv,
    sender_key_name: &SenderKeyName,
) -> Result<JObject<'a>, SignalJniError> {
    let sender_key_name_class =
        env.find_class("org/whispersystems/libsignal/groups/SenderKeyName")?;
    let sender_key_name_ctor_args = [
        JObject::from(env.new_string(sender_key_name.group_id()?)?).into(),
        JObject::from(env.new_string(sender_key_name.sender_name()?)?).into(),
        JValue::from(jint_from_u32(sender_key_name.sender_device_id())?),
    ];

    let sender_key_name_ctor_sig = "(Ljava/lang/String;Ljava/lang/String;I)V";
    let sender_key_name_jobject = env.new_object(
        sender_key_name_class,
        sender_key_name_ctor_sig,
        &sender_key_name_ctor_args,
    )?;
    Ok(sender_key_name_jobject)
}

fn protocol_address_to_jobject<'a>(
    env: &'a JNIEnv,
    address: &ProtocolAddress,
) -> Result<JObject<'a>, SignalJniError> {
    let address_class = env.find_class("org/whispersystems/libsignal/SignalProtocolAddress")?;
    let address_ctor_args = [
        JObject::from(env.new_string(address.name())?).into(),
        JValue::from(jint_from_u32(Ok(address.device_id()))?),
    ];

    let address_ctor_sig = "(Ljava/lang/String;I)V";
    let address_jobject = env.new_object(address_class, address_ctor_sig, &address_ctor_args)?;
    Ok(address_jobject)
}

pub struct JniIdentityKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: jobject,
}

impl<'a> JniIdentityKeyStore<'a> {
    fn new(env: &'a JNIEnv, store: jobject) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/state/IdentityKeyStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniIdentityKeyStore<'a> {
    fn do_get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalJniError> {
        let callback_sig = "()Lorg/whispersystems/libsignal/IdentityKeyPair;";
        let bits = get_object_with_serialization(
            self.env,
            self.store,
            &[],
            callback_sig,
            "getIdentityKeyPair",
        )?;

        match bits {
            None => Err(SignalJniError::Signal(SignalProtocolError::InternalError(
                "getIdentityKeyPair returned null",
            ))),
            Some(k) => Ok(IdentityKeyPair::try_from(k.as_ref())?),
        }
    }

    fn do_get_local_registration_id(&self) -> Result<u32, SignalJniError> {
        let callback_sig = "()I";

        let rvalue =
            self.env
                .call_method(self.store, "getLocalRegistrationId", callback_sig, &[])?;
        exception_check(self.env, "getLocalRegistrationId")?;

        match rvalue {
            JValue::Int(i) => jint_to_u32(i),
            _ => Err(SignalJniError::UnexpectedJniResultType(
                "getLocalRegistrationId",
                rvalue.type_name(),
            )),
        }
    }

    fn do_save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let key_jobject = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/IdentityKey",
            identity.serialize().as_ref(),
        )?;
        let callback_sig = "(Lorg/whispersystems/libsignal/SignalProtocolAddress;Lorg/whispersystems/libsignal/IdentityKey;)Z";
        let callback_args = [address_jobject.into(), key_jobject.into()];
        let result =
            self.env
                .call_method(self.store, "saveIdentity", callback_sig, &callback_args)?;
        exception_check(self.env, "saveIdentity")?;

        match result {
            JValue::Bool(b) => Ok(b != 0),
            _ => Err(SignalJniError::UnexpectedJniResultType(
                "saveIdentity",
                result.type_name(),
            )),
        }
    }

    fn do_is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let key_jobject = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/IdentityKey",
            identity.serialize().as_ref(),
        )?;

        let direction_class = self
            .env
            .find_class("org/whispersystems/libsignal/state/IdentityKeyStore$Direction")?;
        let field_name = match direction {
            Direction::Sending => "SENDING",
            Direction::Receiving => "RECEIVING",
        };

        let field_value = self.env.get_static_field(
            direction_class,
            field_name,
            "Lorg/whispersystems/libsignal/state/IdentityKeyStore$Direction;",
        )?;

        let callback_sig = "(Lorg/whispersystems/libsignal/SignalProtocolAddress;Lorg/whispersystems/libsignal/IdentityKey;Lorg/whispersystems/libsignal/state/IdentityKeyStore$Direction;)Z";
        let callback_args = [address_jobject.into(), key_jobject.into(), field_value];
        let result = self.env.call_method(
            self.store,
            "isTrustedIdentity",
            callback_sig,
            &callback_args,
        )?;
        exception_check(self.env, "isTrustedIdentity")?;

        match result {
            JValue::Bool(b) => Ok(b != 0),
            _ => Err(SignalJniError::UnexpectedJniResultType(
                "isTrustedIdentity",
                result.type_name(),
            )),
        }
    }

    fn do_get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let callback_sig = "(Lorg/whispersystems/libsignal/SignalProtocolAddress;)Lorg/whispersystems/libsignal/IdentityKey;";
        let callback_args = [address_jobject.into()];

        let bits = get_object_with_serialization(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "getIdentity",
        )?;

        match bits {
            None => Ok(None),
            Some(k) => Ok(Some(IdentityKey::decode(&k)?)),
        }
    }
}

#[async_trait(?Send)]
impl<'a> IdentityKeyStore for JniIdentityKeyStore<'a> {
    async fn get_identity_key_pair(
        &self,
        _ctx: Context,
    ) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(self.do_get_identity_key_pair()?)
    }

    async fn get_local_registration_id(&self, _ctx: Context) -> Result<u32, SignalProtocolError> {
        Ok(self.do_get_local_registration_id()?)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self.do_save_identity(address, identity)?)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self.do_is_trusted_identity(address, identity, direction)?)
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        Ok(self.do_get_identity(address)?)
    }
}

pub struct JniPreKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: jobject,
}

impl<'a> JniPreKeyStore<'a> {
    fn new(env: &'a JNIEnv, store: jobject) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/state/PreKeyStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniPreKeyStore<'a> {
    fn do_get_pre_key(&self, prekey_id: u32) -> Result<PreKeyRecord, SignalJniError> {
        let callback_sig = "(I)Lorg/whispersystems/libsignal/state/PreKeyRecord;";
        let callback_args = [JValue::from(jint_from_u32(Ok(prekey_id))?)];
        let pk = get_object_with_native_handle::<PreKeyRecord>(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "loadPreKey",
        )?;
        match pk {
            Some(pk) => Ok(pk),
            None => Err(SignalJniError::Signal(SignalProtocolError::InvalidPreKeyId)),
        }
    }

    fn do_save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &PreKeyRecord,
    ) -> Result<(), SignalJniError> {
        let jobject_record = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/state/PreKeyRecord",
            &record.serialize()?,
        )?;
        let callback_sig = "(I,Lorg/whispersystems/libsignal/state/PreKeyRecord;)V";
        let callback_args = [
            JValue::from(jint_from_u32(Ok(prekey_id))?),
            jobject_record.into(),
        ];
        self.env
            .call_method(self.store, "storePreKey", callback_sig, &callback_args)?;
        exception_check(self.env, "storePreKey")?;
        Ok(())
    }

    fn do_remove_pre_key(&mut self, prekey_id: u32) -> Result<(), SignalJniError> {
        let callback_sig = "(I)V";
        let callback_args = [JValue::from(jint_from_u32(Ok(prekey_id))?)];
        self.env
            .call_method(self.store, "removePreKey", callback_sig, &callback_args)?;
        exception_check(self.env, "removePreKey")?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a> PreKeyStore for JniPreKeyStore<'a> {
    async fn get_pre_key(
        &self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_pre_key(prekey_id)?)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_pre_key(prekey_id, record)?)
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_remove_pre_key(prekey_id)?)
    }
}

pub struct JniSignedPreKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: jobject,
}

impl<'a> JniSignedPreKeyStore<'a> {
    fn new(env: &'a JNIEnv, store: jobject) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/state/SignedPreKeyStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniSignedPreKeyStore<'a> {
    fn do_get_signed_pre_key(&self, prekey_id: u32) -> Result<SignedPreKeyRecord, SignalJniError> {
        let callback_sig = "(I)Lorg/whispersystems/libsignal/state/SignedPreKeyRecord;";
        let callback_args = [JValue::from(jint_from_u32(Ok(prekey_id))?)];
        let spk = get_object_with_native_handle::<SignedPreKeyRecord>(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "loadSignedPreKey",
        )?;
        match spk {
            Some(spk) => Ok(spk),
            None => Err(SignalJniError::Signal(
                SignalProtocolError::InvalidSignedPreKeyId,
            )),
        }
    }

    fn do_save_signed_pre_key(
        &mut self,
        prekey_id: u32,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalJniError> {
        let jobject_record = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/state/SignedPreKeyRecord",
            &record.serialize()?,
        )?;
        let callback_sig = "(I,Lorg/whispersystems/libsignal/state/SignedPreKeyRecord;)V";
        let callback_args = [
            JValue::from(jint_from_u32(Ok(prekey_id))?),
            jobject_record.into(),
        ];
        self.env.call_method(
            self.store,
            "storeSignedPreKey",
            callback_sig,
            &callback_args,
        )?;
        exception_check(self.env, "storeSignedPreKey")?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a> SignedPreKeyStore for JniSignedPreKeyStore<'a> {
    async fn get_signed_pre_key(
        &self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_signed_pre_key(prekey_id)?)
    }

    async fn save_signed_pre_key(
        &mut self,
        prekey_id: u32,
        record: &SignedPreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_signed_pre_key(prekey_id, record)?)
    }
}

pub struct JniSessionStore<'a> {
    env: &'a JNIEnv<'a>,
    store: jobject,
}

impl<'a> JniSessionStore<'a> {
    fn new(env: &'a JNIEnv, store: jobject) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/state/SessionStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniSessionStore<'a> {
    fn do_load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;

        let callback_sig = "(Lorg/whispersystems/libsignal/SignalProtocolAddress;)Lorg/whispersystems/libsignal/state/SessionRecord;";
        let callback_args = [address_jobject.into()];
        let session = get_object_with_serialization(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "loadSession",
        )?;

        match session {
            None => Ok(None),
            Some(s) => Ok(Some(SessionRecord::deserialize(&s)?)),
        }
    }

    fn do_store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let session_jobject = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/state/SessionRecord",
            &record.serialize()?,
        )?;

        let callback_sig = "(Lorg/whispersystems/libsignal/SignalProtocolAddress;Lorg/whispersystems/libsignal/state/SessionRecord;)V";
        let callback_args = [address_jobject.into(), session_jobject.into()];
        self.env
            .call_method(self.store, "storeSession", callback_sig, &callback_args)?;
        exception_check(self.env, "storeSession")?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a> SessionStore for JniSessionStore<'a> {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        Ok(self.do_load_session(address)?)
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_store_session(address, record)?)
    }
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SessionBuilder_1ProcessPreKeyBundle(
    env: JNIEnv,
    _class: JClass,
    bundle: ObjectHandle,
    protocol_address: ObjectHandle,
    session_store: JavaSessionStore,
    identity_key_store: JavaIdentityKeyStore,
) {
    run_ffi_safe(&env, || {
        let bundle = native_handle_cast::<PreKeyBundle>(bundle)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;

        let mut identity_key_store = JniIdentityKeyStore::new(&env, identity_key_store)?;
        let mut session_store = JniSessionStore::new(&env, session_store)?;

        let mut csprng = rand::rngs::OsRng;
        expect_ready(process_prekey_bundle(
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            bundle,
            &mut csprng,
            None,
        ))?;

        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SessionCipher_1EncryptMessage(
    env: JNIEnv,
    _class: JClass,
    message: jbyteArray,
    protocol_address: ObjectHandle,
    session_store: JavaSessionStore,
    identity_key_store: JavaIdentityKeyStore,
) -> JavaCiphertextMessage {
    run_ffi_safe(&env, || {
        let message = env.convert_byte_array(message)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;

        let mut identity_key_store = JniIdentityKeyStore::new(&env, identity_key_store)?;
        let mut session_store = JniSessionStore::new(&env, session_store)?;

        let ctext = expect_ready(message_encrypt(
            &message,
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            None,
        ))?;

        let obj = match ctext {
            CiphertextMessage::SignalMessage(m) => jobject_from_native_handle(
                &env,
                "org/whispersystems/libsignal/protocol/SignalMessage",
                box_object::<SignalMessage>(Ok(m))?,
            ),
            CiphertextMessage::PreKeySignalMessage(m) => jobject_from_native_handle(
                &env,
                "org/whispersystems/libsignal/protocol/PreKeySignalMessage",
                box_object::<PreKeySignalMessage>(Ok(m))?,
            ),
            _ => Err(SignalJniError::Signal(SignalProtocolError::InternalError(
                "Unexpected result type from message_encrypt",
            ))),
        };

        Ok(obj?.into_inner())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SessionCipher_1DecryptSignalMessage(
    env: JNIEnv,
    _class: JClass,
    message: ObjectHandle,
    protocol_address: ObjectHandle,
    session_store: JavaSessionStore,
    identity_key_store: JavaIdentityKeyStore,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let message = native_handle_cast::<SignalMessage>(message)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;

        let mut identity_key_store = JniIdentityKeyStore::new(&env, identity_key_store)?;
        let mut session_store = JniSessionStore::new(&env, session_store)?;

        let mut csprng = rand::rngs::OsRng;
        let ptext = expect_ready(message_decrypt_signal(
            &message,
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            &mut csprng,
            None,
        ))?;

        to_jbytearray(&env, Ok(ptext))
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SessionCipher_1DecryptPreKeySignalMessage(
    env: JNIEnv,
    _class: JClass,
    message: ObjectHandle,
    protocol_address: ObjectHandle,
    session_store: JavaSessionStore,
    identity_key_store: JavaIdentityKeyStore,
    prekey_store: JavaPreKeyStore,
    signed_prekey_store: JavaSignedPreKeyStore,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let message = native_handle_cast::<PreKeySignalMessage>(message)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;
        let mut identity_key_store = JniIdentityKeyStore::new(&env, identity_key_store)?;
        let mut session_store = JniSessionStore::new(&env, session_store)?;
        let mut prekey_store = JniPreKeyStore::new(&env, prekey_store)?;
        let mut signed_prekey_store = JniSignedPreKeyStore::new(&env, signed_prekey_store)?;

        let mut csprng = rand::rngs::OsRng;
        let ptext = expect_ready(message_decrypt_prekey(
            &message,
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            &mut prekey_store,
            &mut signed_prekey_store,
            &mut csprng,
            None,
        ))?;

        to_jbytearray(&env, Ok(ptext))
    })
}

pub struct JniSenderKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: jobject,
}

impl<'a> JniSenderKeyStore<'a> {
    fn new(env: &'a JNIEnv, store: jobject) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/groups/state/SenderKeyStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniSenderKeyStore<'a> {
    fn do_store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalJniError> {
        let sender_key_name_jobject = sender_key_name_to_jobject(self.env, sender_key_name)?;
        let sender_key_record_jobject = jobject_from_native_handle(
            self.env,
            "org/whispersystems/libsignal/groups/state/SenderKeyRecord",
            box_object::<SenderKeyRecord>(Ok(record.clone()))?,
        )?;

        let callback_args = [
            sender_key_name_jobject.into(),
            sender_key_record_jobject.into(),
        ];
        let callback_sig = "(Lorg/whispersystems/libsignal/groups/SenderKeyName;Lorg/whispersystems/libsignal/groups/state/SenderKeyRecord;)V";
        self.env.call_method(
            self.store,
            "storeSenderKey",
            callback_sig,
            &callback_args[..],
        )?;
        exception_check(self.env, "storeSenderKey")?;

        Ok(())
    }

    fn do_load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> Result<Option<SenderKeyRecord>, SignalJniError> {
        let sender_key_name_jobject = sender_key_name_to_jobject(self.env, sender_key_name)?;
        let callback_args = [sender_key_name_jobject.into()];
        let callback_sig = "(Lorg/whispersystems/libsignal/groups/SenderKeyName;)Lorg/whispersystems/libsignal/groups/state/SenderKeyRecord;";

        let skr = get_object_with_native_handle::<SenderKeyRecord>(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "loadSenderKey",
        )?;

        Ok(skr)
    }
}

#[async_trait(?Send)]
impl<'a> SenderKeyStore for JniSenderKeyStore<'a> {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_store_sender_key(sender_key_name, record)?)
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        _ctx: Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        Ok(self.do_load_sender_key(sender_key_name)?)
    }
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_GroupSessionBuilder_1CreateSenderKeyDistributionMessage(
    env: JNIEnv,
    _class: JClass,
    sender_key_name: ObjectHandle,
    store: JavaSenderKeyStore,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let sender_key_name = native_handle_cast::<SenderKeyName>(sender_key_name)?;
        let mut sender_key_store = JniSenderKeyStore::new(&env, store)?;
        let mut csprng = rand::rngs::OsRng;

        let skdm = expect_ready(create_sender_key_distribution_message(
            &sender_key_name,
            &mut sender_key_store,
            &mut csprng,
            None,
        ))?;
        box_object::<SenderKeyDistributionMessage>(Ok(skdm))
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_GroupSessionBuilder_1ProcessSenderKeyDistributionMessage(
    env: JNIEnv,
    _class: JClass,
    sender_key_name: ObjectHandle,
    sender_key_distribution_message: ObjectHandle,
    store: JavaSenderKeyStore,
) {
    run_ffi_safe(&env, || {
        let sender_key_name = native_handle_cast::<SenderKeyName>(sender_key_name)?;
        let sender_key_distribution_message =
            native_handle_cast::<SenderKeyDistributionMessage>(sender_key_distribution_message)?;
        let mut sender_key_store = JniSenderKeyStore::new(&env, store)?;

        expect_ready(process_sender_key_distribution_message(
            sender_key_name,
            sender_key_distribution_message,
            &mut sender_key_store,
            None,
        ))?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_GroupCipher_1EncryptMessage(
    env: JNIEnv,
    _class: JClass,
    sender_key_name: ObjectHandle,
    message: jbyteArray,
    store: JavaSenderKeyStore,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let sender_key_name = native_handle_cast::<SenderKeyName>(sender_key_name)?;
        let message = env.convert_byte_array(message)?;
        let mut sender_key_store = JniSenderKeyStore::new(&env, store)?;

        let mut rng = rand::rngs::OsRng;

        let ctext = expect_ready(group_encrypt(
            &mut sender_key_store,
            &sender_key_name,
            &message,
            &mut rng,
            None,
        ))?;

        to_jbytearray(&env, Ok(ctext))
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_GroupCipher_1DecryptMessage(
    env: JNIEnv,
    _class: JClass,
    sender_key_name: ObjectHandle,
    message: jbyteArray,
    store: JavaSenderKeyStore,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let sender_key_name = native_handle_cast::<SenderKeyName>(sender_key_name)?;
        let message = env.convert_byte_array(message)?;
        let mut sender_key_store = JniSenderKeyStore::new(&env, store)?;

        let ptext = expect_ready(group_decrypt(
            &message,
            &mut sender_key_store,
            &sender_key_name,
            None,
        ))?;

        to_jbytearray(&env, Ok(ptext))
    })
}

// The following are just exposed to make it possible to retain some of the Java tests:

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SessionState_1InitializeAliceSession(
    env: JNIEnv,
    _class: JClass,
    identity_key_private: ObjectHandle,
    identity_key_public: ObjectHandle,
    base_private: ObjectHandle,
    base_public: ObjectHandle,
    their_identity_key: ObjectHandle,
    their_signed_prekey: ObjectHandle,
    their_ratchet_key: ObjectHandle,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let identity_key_private = native_handle_cast::<PrivateKey>(identity_key_private)?;
        let identity_key_public = native_handle_cast::<PublicKey>(identity_key_public)?;
        let base_private = native_handle_cast::<PrivateKey>(base_private)?;
        let base_public = native_handle_cast::<PublicKey>(base_public)?;
        let their_identity_key = native_handle_cast::<PublicKey>(their_identity_key)?;
        let their_signed_prekey = native_handle_cast::<PublicKey>(their_signed_prekey)?;
        let their_ratchet_key = native_handle_cast::<PublicKey>(their_ratchet_key)?;

        let our_identity_key_pair = IdentityKeyPair::new(
            IdentityKey::new(*identity_key_public),
            *identity_key_private,
        );

        let our_base_key_pair = KeyPair::new(*base_public, *base_private);

        let their_identity_key = IdentityKey::new(*their_identity_key);

        let mut csprng = rand::rngs::OsRng;

        let parameters = AliceSignalProtocolParameters::new(
            our_identity_key_pair,
            our_base_key_pair,
            their_identity_key,
            *their_signed_prekey,
            None,
            *their_ratchet_key,
        );

        let session = initialize_alice_session(&parameters, &mut csprng)?;

        to_jbytearray(&env, session.serialize())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SessionState_1InitializeBobSession(
    env: JNIEnv,
    _class: JClass,
    identity_key_private: ObjectHandle,
    identity_key_public: ObjectHandle,
    signed_prekey_private: ObjectHandle,
    signed_prekey_public: ObjectHandle,
    eph_private: ObjectHandle,
    eph_public: ObjectHandle,
    their_identity_key: ObjectHandle,
    their_base_key: ObjectHandle,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let identity_key_private = native_handle_cast::<PrivateKey>(identity_key_private)?;
        let identity_key_public = native_handle_cast::<PublicKey>(identity_key_public)?;
        let signed_prekey_private = native_handle_cast::<PrivateKey>(signed_prekey_private)?;
        let signed_prekey_public = native_handle_cast::<PublicKey>(signed_prekey_public)?;
        let eph_private = native_handle_cast::<PrivateKey>(eph_private)?;
        let eph_public = native_handle_cast::<PublicKey>(eph_public)?;
        let their_identity_key = native_handle_cast::<PublicKey>(their_identity_key)?;
        let their_base_key = native_handle_cast::<PublicKey>(their_base_key)?;

        let our_identity_key_pair = IdentityKeyPair::new(
            IdentityKey::new(*identity_key_public),
            *identity_key_private,
        );

        let our_signed_pre_key_pair = KeyPair::new(*signed_prekey_public, *signed_prekey_private);

        let our_ratchet_key_pair = KeyPair::new(*eph_public, *eph_private);

        let their_identity_key = IdentityKey::new(*their_identity_key);

        let parameters = BobSignalProtocolParameters::new(
            our_identity_key_pair,
            our_signed_pre_key_pair,
            None,
            our_ratchet_key_pair,
            their_identity_key,
            *their_base_key,
        );

        let session = initialize_bob_session(&parameters)?;

        to_jbytearray(&env, session.serialize())
    })
}
