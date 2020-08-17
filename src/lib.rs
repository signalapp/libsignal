#![allow(clippy::missing_safety_doc)]

use jni::objects::{JClass, JString, JValue, JObject};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring, jobject};
use jni::JNIEnv;
use libsignal_protocol_rust::*;
use std::convert::TryFrom;

mod util;

use crate::util::*;

struct SeedAndIteration {
    seed: Vec<u8>,
    iteration: u32
}

impl SeedAndIteration {
    fn new(seed: Vec<u8>, iteration: u32) -> Self {
        Self { seed, iteration }
    }

    fn seed(&self) -> Result<Vec<u8>, SignalProtocolError> {
        Ok(self.seed.clone())
    }

    fn iteration(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.iteration)
    }
}

/* SeedAndIteration (utility class) */
#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_util_SeedAndIteration_New(
    env: JNIEnv,
    _class: JClass,
    seed: jbyteArray,
    iteration: jint
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let seed = env.convert_byte_array(seed)?;
        let iteration = jint_to_u32(iteration)?;
        box_object::<SeedAndIteration>(Ok(SeedAndIteration::new(seed, iteration)))
    })
}

jni_fn_destroy!(Java_org_whispersystems_libsignal_util_SeedAndIteration_Destroy destroys SeedAndIteration);

jni_fn_get_jint!(Java_org_whispersystems_libsignal_util_SeedAndIteration_GetIteration(SeedAndIteration) using
                 |si: &SeedAndIteration| si.iteration());

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_util_SeedAndIteration_GetSeed(SeedAndIteration) using
                       |si: &SeedAndIteration| si.seed());

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_SignalProtocolAddress_New(
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

jni_fn_destroy!(Java_org_whispersystems_libsignal_SignalProtocolAddress_Destroy destroys ProtocolAddress);

jni_fn_get_jstring!(Java_org_whispersystems_libsignal_SignalProtocolAddress_Name(ProtocolAddress) using
                    |p: &ProtocolAddress| Ok(p.name().to_string()));

jni_fn_get_jint!(Java_org_whispersystems_libsignal_SignalProtocolAddress_DeviceId(ProtocolAddress) using
                 |obj: &ProtocolAddress| { Ok(obj.device_id()) });

jni_fn_deserialize!(Java_org_whispersystems_libsignal_ecc_ECPublicKey_Deserialize is PublicKey::deserialize);

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_ecc_ECPublicKey_Serialize(PublicKey) using
                       |k: &PublicKey| Ok(k.serialize()));

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_ecc_ECPublicKey_Verify(
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

jni_fn_destroy!(Java_org_whispersystems_libsignal_ecc_ECPublicKey_Destroy destroys PublicKey);

jni_fn_deserialize!(Java_org_whispersystems_libsignal_ecc_ECPrivateKey_Deserialize is PrivateKey::deserialize);

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_ecc_ECPrivateKey_Serialize(PrivateKey) using
                       |k: &PrivateKey| Ok(k.serialize()));

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_ecc_ECPrivateKey_Generate(
    env: JNIEnv,
    _class: JClass,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let mut rng = rand::rngs::OsRng;
        let keypair = KeyPair::generate(&mut rng);
        box_object::<PrivateKey>(Ok(keypair.private_key))
    })
}

jni_fn_get_new_boxed_obj!(Java_org_whispersystems_libsignal_ecc_ECPrivateKey_GetPublicKey(PublicKey) from PrivateKey,
                          |k: &PrivateKey| k.public_key());

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_ecc_ECPrivateKey_Sign(
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
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_ecc_ECPrivateKey_Agree(
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

jni_fn_destroy!(Java_org_whispersystems_libsignal_ecc_ECPrivateKey_Destroy destroys PrivateKey);

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_fingerprint_DisplayableFingerprint_Format(
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
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_fingerprint_NumericFingerprintGenerator_New(
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

jni_fn_destroy!(Java_org_whispersystems_libsignal_fingerprint_NumericFingerprintGenerator_Destroy destroys Fingerprint);

jni_fn_get_jstring!(Java_org_whispersystems_libsignal_fingerprint_NumericFingerprintGenerator_GetDisplayString(Fingerprint) using
    Fingerprint::display_string);

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_fingerprint_NumericFingerprintGenerator_GetScannableEncoding(Fingerprint) using
                       |f: &Fingerprint| f.scannable.serialize());

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_fingerprint_ScannableFingerprint_Compare(
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
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_kdf_HKDF_DeriveSecrets(
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

        let info = env.convert_byte_array(info)?;

        let hkdf = HKDF::new(version)?;
        let derived = if let Some(salt) = salt {
            hkdf.derive_salted_secrets(&input_key_material, &salt, &info, output_length)
        } else {
            hkdf.derive_secrets(&input_key_material, &info, output_length)
        };

        to_jbytearray(&env, derived)
    })
}

jni_fn_deserialize!(Java_org_whispersystems_libsignal_protocol_SignalMessage_Deserialize is SignalMessage::try_from);

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_protocol_SignalMessage_New(
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

jni_fn_destroy!(Java_org_whispersystems_libsignal_protocol_SignalMessage_Destroy destroys SignalMessage);

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_protocol_SignalMessage_GetSenderRatchetKey(SignalMessage) using
                       |m: &SignalMessage| Ok(m.sender_ratchet_key().serialize()));

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_protocol_SignalMessage_GetBody(SignalMessage) using
                       |m: &SignalMessage| Ok(m.body().to_vec()));
jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_protocol_SignalMessage_GetSerialized(SignalMessage) using
                       |m: &SignalMessage| Ok(m.serialized().to_vec()));

jni_fn_get_jint!(Java_org_whispersystems_libsignal_protocol_SignalMessage_GetMessageVersion(SignalMessage) using
                 |msg: &SignalMessage| { Ok(msg.message_version() as u32) });

jni_fn_get_jint!(Java_org_whispersystems_libsignal_protocol_SignalMessage_GetCounter(SignalMessage) using
                 |msg: &SignalMessage| { Ok(msg.counter()) });

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_protocol_SignalMessage_VerifyMac(
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

jni_fn_deserialize!(Java_org_whispersystems_libsignal_protocol_PreKeySignalMessage_Deserialize is PreKeySignalMessage::try_from);

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_protocol_PreKeySignalMessage_New(
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

jni_fn_destroy!(Java_org_whispersystems_libsignal_protocol_PreKeySignalMessage_Destroy destroys PreKeySignalMessage);

jni_fn_get_jint!(Java_org_whispersystems_libsignal_protocol_PreKeySignalMessage_GetVersion(PreKeySignalMessage) using
                 |m: &PreKeySignalMessage| Ok(m.message_version() as u32));

jni_fn_get_jint!(Java_org_whispersystems_libsignal_protocol_PreKeySignalMessage_GetRegistrationId(PreKeySignalMessage) using
                 |m: &PreKeySignalMessage| Ok(m.registration_id()));

// Special logic to handle optionality:
#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_protocol_PreKeySignalMessage_GetPreKeyId(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
) -> jint {
    run_ffi_safe(&env, || {
        let pksm = native_handle_cast::<PreKeySignalMessage>(handle)?;
        match pksm.pre_key_id() {
            Some(id) => jint_from_u32(Ok(id)),
            None => Ok(-1 as jint),
        }
    })
}

jni_fn_get_jint!(Java_org_whispersystems_libsignal_protocol_PreKeySignalMessage_GetSignedPreKeyId(PreKeySignalMessage) using
                 |m: &PreKeySignalMessage| Ok(m.signed_pre_key_id()));

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_protocol_PreKeySignalMessage_GetBaseKey(PreKeySignalMessage) using
                       |m: &PreKeySignalMessage| Ok(m.base_key().serialize()));

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_protocol_PreKeySignalMessage_GetIdentityKey(PreKeySignalMessage) using
                       |m: &PreKeySignalMessage| Ok(m.identity_key().serialize()));

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_protocol_PreKeySignalMessage_GetSignalMessage(PreKeySignalMessage) using
                       |m: &PreKeySignalMessage| Ok(m.message().serialized().to_vec()));

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_protocol_PreKeySignalMessage_GetSerialized(PreKeySignalMessage) using
                       |m: &PreKeySignalMessage| Ok(m.serialized().to_vec()));

jni_fn_deserialize!(Java_org_whispersystems_libsignal_protocol_SenderKeyMessage_Deserialize is SenderKeyMessage::try_from);

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_protocol_SenderKeyMessage_New(
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

jni_fn_deserialize!(Java_org_whispersystems_libsignal_protocol_SenderKeyDistributionMessage_Deserialize is SenderKeyDistributionMessage::try_from);

jni_fn_destroy!(Java_org_whispersystems_libsignal_protocol_SenderKeyMessage_Destroy destroys SenderKeyMessage);

jni_fn_get_jint!(Java_org_whispersystems_libsignal_protocol_SenderKeyMessage_GetKeyId(SenderKeyMessage) using
                 |m: &SenderKeyMessage| Ok(m.key_id()));

jni_fn_get_jint!(Java_org_whispersystems_libsignal_protocol_SenderKeyMessage_GetIteration(SenderKeyMessage) using
                 |m: &SenderKeyMessage| Ok(m.iteration()));

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_protocol_SenderKeyMessage_GetCipherText(SenderKeyMessage) using
                       |m: &SenderKeyMessage| Ok(m.ciphertext().to_vec()));

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_protocol_SenderKeyMessage_GetSerialized(SenderKeyMessage) using
                       |m: &SenderKeyMessage| Ok(m.serialized().to_vec()));

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_protocol_SenderKeyMessage_VerifySignature(
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
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_protocol_SenderKeyDistributionMessage_New(
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

jni_fn_destroy!(Java_org_whispersystems_libsignal_protocol_SenderKeyDistributionMessage_Destroy destroys SenderKeyDistributionMessage);

jni_fn_get_jint!(Java_org_whispersystems_libsignal_protocol_SenderKeyDistributionMessage_GetId(SenderKeyDistributionMessage) using
                 |m: &SenderKeyDistributionMessage| m.id());

jni_fn_get_jint!(Java_org_whispersystems_libsignal_protocol_SenderKeyDistributionMessage_GetIteration(SenderKeyDistributionMessage) using
                 |m: &SenderKeyDistributionMessage| m.iteration());

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_protocol_SenderKeyDistributionMessage_GetChainKey(SenderKeyDistributionMessage) using
                       |m: &SenderKeyDistributionMessage| Ok(m.chain_key()?.to_vec()));

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_protocol_SenderKeyDistributionMessage_GetSignatureKey(SenderKeyDistributionMessage) using
                       |m: &SenderKeyDistributionMessage| Ok(m.signing_key()?.serialize()));

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_protocol_SenderKeyDistributionMessage_GetSerialized(SenderKeyDistributionMessage) using
                       |m: &SenderKeyDistributionMessage| Ok(m.serialized().to_vec()));

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_state_PreKeyBundle_New(
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

jni_fn_destroy!(Java_org_whispersystems_libsignal_state_PreKeyBundle_Destroy destroys PreKeyBundle);

jni_fn_get_jint!(Java_org_whispersystems_libsignal_state_PreKeyBundle_GetRegistrationId(PreKeyBundle) using
                 |m: &PreKeyBundle| m.registration_id());

jni_fn_get_jint!(Java_org_whispersystems_libsignal_state_PreKeyBundle_GetDeviceId(PreKeyBundle) using
                 |m: &PreKeyBundle| m.device_id());

jni_fn_get_jint!(Java_org_whispersystems_libsignal_state_PreKeyBundle_GetSignedPreKeyId(PreKeyBundle) using
                 |m: &PreKeyBundle| m.signed_pre_key_id());

// Special logic for optional here:
#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_state_PreKeyBundle_GetPreKeyId(
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

jni_fn_get_new_boxed_optional_obj!(Java_org_whispersystems_libsignal_state_PreKeyBundle_GetPreKeyPublic(PublicKey) from PreKeyBundle,
                                   |p: &PreKeyBundle| p.pre_key_public());

jni_fn_get_new_boxed_obj!(Java_org_whispersystems_libsignal_state_PreKeyBundle_GetSignedPreKeyPublic(PublicKey) from PreKeyBundle,
                          |p: &PreKeyBundle| Ok(p.signed_pre_key_public()?));

jni_fn_get_new_boxed_obj!(Java_org_whispersystems_libsignal_state_PreKeyBundle_GetIdentityKey(PublicKey) from PreKeyBundle,
                          |p: &PreKeyBundle| Ok(*p.identity_key()?.public_key()));

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_state_PreKeyBundle_GetSignedPreKeySignature(PreKeyBundle) using
                       |m: &PreKeyBundle| Ok(m.signed_pre_key_signature()?.to_vec()));

/* SignedPreKeyRecord */

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_state_SignedPreKeyRecord_New(
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

jni_fn_deserialize!(Java_org_whispersystems_libsignal_state_SignedPreKeyRecord_Deserialize is SignedPreKeyRecord::deserialize);

jni_fn_get_jint!(Java_org_whispersystems_libsignal_state_SignedPreKeyRecord_GetId(SignedPreKeyRecord) using
                 |m: &SignedPreKeyRecord| m.id());

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_state_SignedPreKeyRecord_GetTimestamp(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
) -> jlong {
    run_ffi_safe(&env, || {
        let spkr = native_handle_cast::<SignedPreKeyRecord>(handle)?;
        jlong_from_u64(spkr.timestamp())
    })
}

jni_fn_get_new_boxed_obj!(Java_org_whispersystems_libsignal_state_SignedPreKeyRecord_GetPublicKey(PublicKey) from SignedPreKeyRecord,
                          |p: &SignedPreKeyRecord| p.public_key());

jni_fn_get_new_boxed_obj!(Java_org_whispersystems_libsignal_state_SignedPreKeyRecord_GetPrivateKey(PrivateKey) from SignedPreKeyRecord,
                          |p: &SignedPreKeyRecord| p.private_key());

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_state_SignedPreKeyRecord_GetSignature(SignedPreKeyRecord) using
                       |m: &SignedPreKeyRecord| m.signature());

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_state_SignedPreKeyRecord_GetSerialized(SignedPreKeyRecord) using
                       |m: &SignedPreKeyRecord| m.serialize());

jni_fn_destroy!(Java_org_whispersystems_libsignal_state_SignedPreKeyRecord_Destroy destroys SignedPreKeyRecord);

/* PreKeyRecord */

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_state_PreKeyRecord_New(
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

jni_fn_deserialize!(Java_org_whispersystems_libsignal_state_PreKeyRecord_Deserialize is PreKeyRecord::deserialize);

jni_fn_get_jint!(Java_org_whispersystems_libsignal_state_PreKeyRecord_GetId(PreKeyRecord) using
                 |m: &PreKeyRecord| m.id());

jni_fn_get_new_boxed_obj!(Java_org_whispersystems_libsignal_state_PreKeyRecord_GetPublicKey(PublicKey) from PreKeyRecord,
                          |p: &PreKeyRecord| p.public_key());

jni_fn_get_new_boxed_obj!(Java_org_whispersystems_libsignal_state_PreKeyRecord_GetPrivateKey(PrivateKey) from PreKeyRecord,
                          |p: &PreKeyRecord| p.private_key());

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_state_PreKeyRecord_GetSerialized(PreKeyRecord) using
                       |m: &PreKeyRecord| m.serialize());

jni_fn_destroy!(Java_org_whispersystems_libsignal_state_PreKeyRecord_Destroy destroys PreKeyRecord);

/* SenderKeyName */

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_groups_SenderKeyName_New(
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

jni_fn_destroy!(Java_org_whispersystems_libsignal_groups_SenderKeyName_Destroy destroys SenderKeyName);

jni_fn_get_jstring!(Java_org_whispersystems_libsignal_groups_SenderKeyName_GetGroupId(SenderKeyName) using
                    SenderKeyName::group_id);

jni_fn_get_jstring!(Java_org_whispersystems_libsignal_groups_SenderKeyName_GetSenderName(SenderKeyName) using
                    |skn: &SenderKeyName| { Ok(skn.sender()?.name().to_string()) });

jni_fn_get_jint!(Java_org_whispersystems_libsignal_groups_SenderKeyName_GetSenderDeviceId(SenderKeyName) using
                 |m: &SenderKeyName| Ok(m.sender()?.device_id()));


#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_groups_state_SenderKeyState_New(
    env: JNIEnv,
    _class: JClass,
    id: jint,
    iteration: jint,
    chain_key: jbyteArray,
    signature_public: ObjectHandle,
    signature_private: ObjectHandle,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let id = jint_to_u32(id)?;
        let iteration = jint_to_u32(iteration)?;
        let chain_key = env.convert_byte_array(chain_key)?;
        let signature_public = native_handle_cast::<PublicKey>(signature_public)?;
        let signature_private = native_handle_cast_optional::<PrivateKey>(signature_private)?.map(|k| *k);

        let sks = SenderKeyState::new(id, iteration, &chain_key, *signature_public, signature_private);
        box_object::<SenderKeyState>(sks)
    })
}

jni_fn_destroy!(Java_org_whispersystems_libsignal_groups_state_SenderKeyState_Destroy destroys SenderKeyState);

jni_fn_deserialize!(Java_org_whispersystems_libsignal_groups_state_SenderKeyState_Deserialize is SenderKeyState::deserialize);

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_groups_state_SenderKeyState_GetSerialized(SenderKeyState) using
                       |sks: &SenderKeyState| sks.serialize());

jni_fn_get_jint!(Java_org_whispersystems_libsignal_groups_state_SenderKeyState_GetKeyId(SenderKeyState) using
                       |sks: &SenderKeyState| sks.sender_key_id());

jni_fn_get_new_boxed_obj!(Java_org_whispersystems_libsignal_groups_state_SenderKeyState_GetSigningKeyPublic(PublicKey) from SenderKeyState,
                          |sks: &SenderKeyState| sks.signing_key_public());

jni_fn_get_new_boxed_optional_obj!(Java_org_whispersystems_libsignal_groups_state_SenderKeyState_GetSigningKeyPrivate(PrivateKey) from SenderKeyState,
                                   |sks: &SenderKeyState| sks.signing_key_private());

jni_fn_get_jbytearray!(Java_org_whispersystems_libsignal_groups_state_SenderKeyState_GetSenderChainKeySeed(SenderKeyState) using
                       |sks: &SenderKeyState| sks.sender_chain_key()?.seed());

jni_fn_get_jint!(Java_org_whispersystems_libsignal_groups_state_SenderKeyState_GetSenderChainKeyIteration(SenderKeyState) using
                 |sks: &SenderKeyState| sks.sender_chain_key()?.iteration());

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_groups_state_SenderKeyState_SetSenderChainKey(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
    iteration: jint,
    seed: jbyteArray) {
    run_ffi_safe(&env, || {
        let sender_key_state = native_handle_cast::<SenderKeyState>(handle)?;
        let iteration = jint_to_u32(iteration)?;
        let seed = env.convert_byte_array(seed)?;

        let sender_chain = SenderChainKey::new(iteration, seed)?;
        sender_key_state.set_sender_chain_key(sender_chain)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_groups_state_SenderKeyState_AddSenderMessageKey(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
    iteration: jint,
    seed: jbyteArray) {
    run_ffi_safe(&env, || {
        let sender_key_state = native_handle_cast::<SenderKeyState>(handle)?;
        let iteration = jint_to_u32(iteration)?;
        let seed = env.convert_byte_array(seed)?;
        let sender_message_key = SenderMessageKey::new(iteration, seed)?;
        sender_key_state.add_sender_message_key(&sender_message_key)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_groups_state_SenderKeyState_HasSenderMessageKey(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
    iteration: jint) -> jboolean {
    run_ffi_safe(&env, || {
        let sender_key_state = native_handle_cast::<SenderKeyState>(handle)?;
        let iteration = jint_to_u32(iteration)?;
        Ok(sender_key_state.has_sender_message_key(iteration)? as jboolean)
    })
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_groups_state_SenderKeyState_RemoveSenderMessageKey(
    env: JNIEnv,
    _class: JClass,
    handle: ObjectHandle,
    iteration: jint) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let sender_key_state = native_handle_cast::<SenderKeyState>(handle)?;
        let iteration = jint_to_u32(iteration)?;

        if let Some(sender_key) = sender_key_state.remove_sender_message_key(iteration)? {
            let sai = SeedAndIteration::new(sender_key.seed()?, sender_key.iteration()?);
            box_object::<SeedAndIteration>(Ok(sai))
        } else {
            Ok(0 as ObjectHandle)
        }
    })
}

fn jobject_from_sender_key_name<'a>(env: &'a JNIEnv, sender_key_name: &SenderKeyName) -> Result<JObject<'a>, SignalJniError> {
    let sender_key_name_class = env.find_class("org/whispersystems/libsignal/groups/SenderKeyName")?;
    let sender_key_name_ctor_args = [
        JObject::from(env.new_string(sender_key_name.group_id()?)?).into(),
        JObject::from(env.new_string(sender_key_name.sender_name()?)?).into(),
        JValue::from(jint_from_u32(sender_key_name.sender_device_id())?)
    ];

    let sender_key_name_ctor_sig = "(Ljava/lang/String;Ljava/lang/String;I)V";
    let sender_key_name_jobject = env.new_object(sender_key_name_class, sender_key_name_ctor_sig, &sender_key_name_ctor_args)?;
    Ok(sender_key_name_jobject)
}

fn jobject_from_sender_key_record<'a>(env: &'a JNIEnv, sender_key_record: &SenderKeyRecord) -> Result<JObject<'a>, SignalJniError> {
    jobject_from_serialized(env, "org/whispersystems/libsignal/groups/state/SenderKeyRecord", &sender_key_record.serialize()?)
}

pub struct JniIdentityKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    obj: jobject,
}

impl<'a> JniIdentityKeyStore<'a> {
    fn new(env: &'a JNIEnv, obj: jobject) -> Self {
        Self { env, obj }
    }
}

impl<'a> JniIdentityKeyStore<'a> {
    fn do_get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalJniError> {
        Err(SignalJniError::Signal(SignalProtocolError::InternalError("todo")))
    }

    fn do_get_local_registration_id(&self) -> Result<u32, SignalJniError> {
        Err(SignalJniError::Signal(SignalProtocolError::InternalError("todo")))
    }

    fn do_save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> Result<bool, SignalJniError> {
        Err(SignalJniError::Signal(SignalProtocolError::InternalError("todo")))
    }

    fn do_is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalJniError> {
        Err(SignalJniError::Signal(SignalProtocolError::InternalError("todo")))
    }

    fn do_get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>, SignalJniError> {
        Err(SignalJniError::Signal(SignalProtocolError::InternalError("todo")))
    }
}

impl<'a> IdentityKeyStore for JniIdentityKeyStore<'a> {

    fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(self.do_get_identity_key_pair()?)
    }

    fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.do_get_local_registration_id()?)
    }

    fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> Result<bool, SignalProtocolError> {
        Ok(self.do_save_identity(address, identity)?)
    }

    fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self.do_is_trusted_identity(address, identity, direction)?)
    }

    fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>, SignalProtocolError> {
        Ok(self.do_get_identity(address)?)
    }
}

pub struct JniPreKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    obj: jobject,
}

impl<'a> JniPreKeyStore<'a> {
    fn new(env: &'a JNIEnv, obj: jobject) -> Self {
        Self { env, obj }
    }
}

impl<'a> JniPreKeyStore<'a> {
    fn do_get_pre_key(&self, prekey_id: u32) -> Result<PreKeyRecord, SignalJniError> {
        Err(SignalJniError::Signal(SignalProtocolError::InternalError("todo")))
    }

    fn do_save_pre_key(&mut self, prekey_id: u32, record: &PreKeyRecord) -> Result<(), SignalJniError> {
        Err(SignalJniError::Signal(SignalProtocolError::InternalError("todo")))
    }

    fn do_remove_pre_key(&mut self, prekey_id: u32) -> Result<(), SignalJniError> {
        Err(SignalJniError::Signal(SignalProtocolError::InternalError("todo")))
    }
}

impl<'a> PreKeyStore for JniPreKeyStore<'a> {
    fn get_pre_key(&self, prekey_id: u32) -> Result<PreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_pre_key(prekey_id)?)
    }

    fn save_pre_key(&mut self, prekey_id: u32, record: &PreKeyRecord) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_pre_key(prekey_id, record)?)
    }

    fn remove_pre_key(&mut self, prekey_id: u32) -> Result<(), SignalProtocolError> {
        Ok(self.do_remove_pre_key(prekey_id)?)
    }
}

pub struct JniSignedPreKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    obj: jobject,
}

impl<'a> JniSignedPreKeyStore<'a> {
    fn new(env: &'a JNIEnv, obj: jobject) -> Self {
        Self { env, obj }
    }
}

impl<'a> JniSignedPreKeyStore<'a> {
    fn do_get_signed_pre_key(&self, prekey_id: u32) -> Result<SignedPreKeyRecord, SignalJniError> {
        Err(SignalJniError::Signal(SignalProtocolError::InternalError("todo")))
    }

    fn do_save_signed_pre_key(&mut self, prekey_id: u32, record: &SignedPreKeyRecord) -> Result<(), SignalJniError> {
        Err(SignalJniError::Signal(SignalProtocolError::InternalError("todo")))
    }
}

impl<'a> SignedPreKeyStore for JniSignedPreKeyStore<'a> {
    fn get_signed_pre_key(&self, prekey_id: u32) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_signed_pre_key(prekey_id)?)
    }

    fn save_signed_pre_key(&mut self, prekey_id: u32, record: &SignedPreKeyRecord) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_signed_pre_key(prekey_id, record)?)
    }
}

pub struct JniSessionStore<'a> {
    env: &'a JNIEnv<'a>,
    obj: jobject,
}

impl<'a> JniSessionStore<'a> {
    fn new(env: &'a JNIEnv, obj: jobject) -> Self {
        Self { env, obj }
    }
}

impl<'a> JniSessionStore<'a> {
    fn do_load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>, SignalJniError> {
        Err(SignalJniError::Signal(SignalProtocolError::InternalError("todo")))
    }

    fn do_store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> Result<(), SignalJniError> {
        Err(SignalJniError::Signal(SignalProtocolError::InternalError("todo")))
    }
}

impl<'a> SessionStore for JniSessionStore<'a> {
    fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>, SignalProtocolError> {
        Ok(self.do_load_session(address)?)
    }

    fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> Result<(), SignalProtocolError> {
        Ok(self.do_store_session(address, record)?)
    }
}

pub struct JniSenderKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    obj: jobject,
}

impl<'a> JniSenderKeyStore<'a> {
    fn new(env: &'a JNIEnv, obj: jobject) -> Self {
        Self { env, obj }
    }
}

impl<'a> JniSenderKeyStore<'a> {
    fn do_store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalJniError> {

        let sender_key_name_jobject = jobject_from_sender_key_name(self.env, sender_key_name)?;
        let sender_key_record_jobject = jobject_from_sender_key_record(self.env, record)?;

        let callback_args = [
            sender_key_name_jobject.into(),
            sender_key_record_jobject.into(),
        ];
        let callback_sig = "(Lorg/whispersystems/libsignal/groups/SenderKeyName;Lorg/whispersystems/libsignal/groups/state/SenderKeyRecord;)V";
        self.env.call_method(self.obj, "storeSenderKey", callback_sig, &callback_args[..])?;
        exception_check(self.env)?;

        Ok(())
    }

    fn do_load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> Result<Option<SenderKeyRecord>, SignalJniError> {

        let sender_key_name_jobject = jobject_from_sender_key_name(self.env, sender_key_name)?;
        let callback_args = [sender_key_name_jobject.into()];
        let callback_sig = "(Lorg/whispersystems/libsignal/groups/SenderKeyName;)Lorg/whispersystems/libsignal/groups/state/SenderKeyRecord;";

        let skr_obj = self.env.call_method(self.obj, "loadSenderKey", callback_sig, &callback_args[..])?;
        exception_check(self.env)?;

        let skr_obj = match skr_obj {
            JValue::Object(o) => *o,
            _ => {
                return Err(SignalJniError::BadJniParameter("loadSenderKey returned non-object"))
            }
        };

        let serialized_bytes = self.env.call_method(skr_obj, "serialize", "()[B", &[])?;
        exception_check(self.env)?;

        match serialized_bytes {
            JValue::Object(o) => {
                let bytes = self.env.convert_byte_array(*o)?;
                let skr = SenderKeyRecord::deserialize(&bytes)?;
                Ok(Some(skr))
            }
            _ => {
                Err(SignalJniError::BadJniParameter("SenderKeyRecord::serialize returned unexpected type"))
            }
        }
    }
}

impl<'a> SenderKeyStore for JniSenderKeyStore<'a> {
    fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_store_sender_key(sender_key_name, record)?)
    }

    fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        Ok(self.do_load_sender_key(sender_key_name)?)
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_groups_GroupSessionBuilder_CreateSenderKeyDistributionMessage(
    env: JNIEnv,
    _class: JClass,
    sender_key_name: ObjectHandle,
    store: jobject) -> ObjectHandle {

    run_ffi_safe(&env, || {
        let sender_key_name = native_handle_cast::<SenderKeyName>(sender_key_name)?;
        let store = check_jobject_type(&env, store, "org/whispersystems/libsignal/groups/state/SenderKeyStore")?;

        let mut sender_key_store = JniSenderKeyStore::new(&env, store);
        let mut csprng = rand::rngs::OsRng;

        let skdm = create_sender_key_distribution_message(&sender_key_name, &mut sender_key_store, &mut csprng)?;
        box_object::<SenderKeyDistributionMessage>(Ok(skdm))
    })
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_groups_GroupSessionBuilder_ProcessSenderKeyDistributionMessage(
    env: JNIEnv,
    _class: JClass,
    sender_key_name: ObjectHandle,
    sender_key_distribution_message: ObjectHandle,
    store: jobject) {

    run_ffi_safe(&env, || {
        let sender_key_name = native_handle_cast::<SenderKeyName>(sender_key_name)?;
        let sender_key_distribution_message = native_handle_cast::<SenderKeyDistributionMessage>(sender_key_distribution_message)?;
        let store = check_jobject_type(&env, store, "org/whispersystems/libsignal/groups/state/SenderKeyStore")?;

        let mut sender_key_store = JniSenderKeyStore::new(&env, store);

        process_sender_key_distribution_message(sender_key_name, sender_key_distribution_message, &mut sender_key_store)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_groups_GroupCipher_EncryptMessage(
    env: JNIEnv,
    _class: JClass,
    sender_key_name: ObjectHandle,
    message: jbyteArray,
    store: jobject) -> jbyteArray {

    run_ffi_safe(&env, || {
        let sender_key_name = native_handle_cast::<SenderKeyName>(sender_key_name)?;
        let message = env.convert_byte_array(message)?;
        let store = check_jobject_type(&env, store, "org/whispersystems/libsignal/groups/state/SenderKeyStore")?;

        let mut sender_key_store = JniSenderKeyStore::new(&env, store);

        let mut rng = rand::rngs::OsRng;

        let ctext = group_encrypt(&mut sender_key_store, &sender_key_name, &message, &mut rng)?;

        to_jbytearray(&env, Ok(ctext))
    })
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_whispersystems_libsignal_groups_GroupCipher_DecryptMessage(
    env: JNIEnv,
    _class: JClass,
    sender_key_name: ObjectHandle,
    message: jbyteArray,
    store: jobject) -> jbyteArray {

    run_ffi_safe(&env, || {
        let sender_key_name = native_handle_cast::<SenderKeyName>(sender_key_name)?;
        let message = env.convert_byte_array(message)?;
        let store = check_jobject_type(&env, store, "org/whispersystems/libsignal/groups/state/SenderKeyStore")?;

        let mut sender_key_store = JniSenderKeyStore::new(&env, store);

        let ptext = group_decrypt(&message, &mut sender_key_store, &sender_key_name)?;

        to_jbytearray(&env, Ok(ptext))
    })
}

