//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]

use aes_gcm_siv::Aes256GcmSiv;
use libsignal_bridge_macros::*;
use libsignal_protocol_rust::*;
use std::convert::TryFrom;

#[cfg(not(any(feature = "ffi", feature = "jni", feature = "node")))]
compile_error!("Feature \"ffi\", \"jni\", or \"node\" must be enabled for this crate.");

#[cfg(feature = "ffi")]
#[macro_use]
pub mod ffi;

#[cfg(feature = "jni")]
#[macro_use]
pub mod jni;

#[cfg(feature = "node")]
#[macro_use]
pub mod node;

#[macro_use]
mod support;
use support::*;

bridge_handle!(Aes256GcmSiv, clone = false);
bridge_handle!(CiphertextMessage, clone = false, jni = false);
bridge_handle!(Fingerprint, jni = NumericFingerprintGenerator);
bridge_handle!(PreKeyBundle);
bridge_handle!(PreKeyRecord);
bridge_handle!(PreKeySignalMessage);
bridge_handle!(PrivateKey, ffi = privatekey, jni = ECPrivateKey);
bridge_handle!(ProtocolAddress, ffi = address);
bridge_handle!(PublicKey, ffi = publickey, jni = ECPublicKey);
bridge_handle!(SenderCertificate);
bridge_handle!(SenderKeyDistributionMessage);
bridge_handle!(SenderKeyMessage);
bridge_handle!(SenderKeyName);
bridge_handle!(SenderKeyRecord);
bridge_handle!(ServerCertificate);
bridge_handle!(SessionRecord);
bridge_handle!(SignalMessage, ffi = message);
bridge_handle!(SignedPreKeyRecord);
bridge_handle!(UnidentifiedSenderMessage, ffi = false, node = false);
bridge_handle!(UnidentifiedSenderMessageContent, clone = false);

#[bridge_fn(ffi = "address_new")]
fn ProtocolAddress_New(name: String, device_id: u32) -> ProtocolAddress {
    ProtocolAddress::new(name, device_id)
}

bridge_deserialize!(PublicKey::deserialize, ffi = publickey, jni = false);
bridge_get_bytearray!(Serialize(PublicKey), ffi = "publickey_serialize", jni = "ECPublicKey_1Serialize" =>
    |k| Ok(k.serialize()));
bridge_get_bytearray!(
    GetPublicKeyBytes(PublicKey),
    ffi = "publickey_get_public_key_bytes",
    jni = "ECPublicKey_1GetPublicKeyBytes" =>
    PublicKey::public_key_bytes
);
bridge_get!(ProtocolAddress::device_id as DeviceId -> u32, ffi = "address_get_device_id");
bridge_get!(ProtocolAddress::name as Name -> String, ffi = "address_get_name");

#[bridge_fn(ffi = "publickey_compare", node = "PublicKey_Compare")]
fn ECPublicKey_Compare(key1: &PublicKey, key2: &PublicKey) -> i32 {
    match key1.cmp(&key2) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

#[bridge_fn(ffi = "publickey_verify", node = "PublicKey_Verify")]
fn ECPublicKey_Verify(
    key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, SignalProtocolError> {
    key.verify_signature(&message, &signature)
}

bridge_deserialize!(
    PrivateKey::deserialize,
    ffi = privatekey,
    jni = ECPrivateKey
);
bridge_get_bytearray!(
    Serialize(PrivateKey),
    ffi = "privatekey_serialize",
    jni = "ECPrivateKey_1Serialize" =>
    |k| Ok(k.serialize())
);

#[bridge_fn(ffi = "privatekey_generate", node = "PrivateKey_Generate")]
fn ECPrivateKey_Generate() -> PrivateKey {
    let mut rng = rand::rngs::OsRng;
    let keypair = KeyPair::generate(&mut rng);
    keypair.private_key
}

#[bridge_fn(ffi = "privatekey_get_public_key", node = "PrivateKey_GetPublicKey")]
fn ECPrivateKey_GetPublicKey(k: &PrivateKey) -> Result<PublicKey, SignalProtocolError> {
    k.public_key()
}

#[bridge_fn_buffer(ffi = "privatekey_sign", node = "PrivateKey_Sign")]
fn ECPrivateKey_Sign<T: Env>(
    env: T,
    key: &PrivateKey,
    message: &[u8],
) -> Result<T::Buffer, SignalProtocolError> {
    let mut rng = rand::rngs::OsRng;
    let sig = key.calculate_signature(&message, &mut rng)?;
    Ok(env.buffer(sig.into_vec()))
}

#[bridge_fn_buffer(ffi = "privatekey_agree", node = "PrivateKey_Agree")]
fn ECPrivateKey_Agree<T: Env>(
    env: T,
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<T::Buffer, SignalProtocolError> {
    let dh_secret = private_key.calculate_agreement(&public_key)?;
    Ok(env.buffer(dh_secret.into_vec()))
}

#[bridge_fn_buffer(ffi = "identitykeypair_serialize")]
fn IdentityKeyPair_Serialize<T: Env>(
    env: T,
    public_key: &PublicKey,
    private_key: &PrivateKey,
) -> Result<T::Buffer, SignalProtocolError> {
    let identity_key_pair = IdentityKeyPair::new(IdentityKey::new(*public_key), *private_key);
    Ok(env.buffer(identity_key_pair.serialize().into_vec()))
}

bridge_get_bytearray!(
    ScannableEncoding(Fingerprint),
    jni = "NumericFingerprintGenerator_1GetScannableEncoding" =>
    |f| f.scannable.serialize()
);
bridge_get!(
    Fingerprint::display_string as DisplayString -> String,
    jni = "NumericFingerprintGenerator_1GetDisplayString"
);

#[bridge_fn(ffi = "fingerprint_format")]
fn DisplayableFingerprint_Format(
    local: &[u8],
    remote: &[u8],
) -> Result<String, SignalProtocolError> {
    DisplayableFingerprint::new(&local, &remote).map(|f| f.to_string())
}
#[bridge_fn(ffi = "fingerprint_compare")]
fn ScannableFingerprint_Compare(
    fprint1: &[u8],
    fprint2: &[u8],
) -> Result<bool, SignalProtocolError> {
    ScannableFingerprint::deserialize(&fprint1)?.compare(fprint2)
}

bridge_deserialize!(SignalMessage::try_from, ffi = message);
bridge_get_bytearray!(GetSenderRatchetKey(SignalMessage), ffi = false, node = false =>
    |m| Ok(m.sender_ratchet_key().serialize())
);
bridge_get_bytearray!(GetBody(SignalMessage), ffi = "message_get_body" =>
    |m| Ok(m.body())
);
bridge_get_bytearray!(GetSerialized(SignalMessage), ffi = "message_get_serialized" =>
    |m| Ok(m.serialized())
);
bridge_get!(SignalMessage::counter -> u32, ffi = "message_get_counter");
bridge_get!(SignalMessage::message_version -> u32, ffi = "message_get_message_version");

#[bridge_fn(ffi = "message_new")]
fn SignalMessage_New(
    message_version: u8,
    mac_key: &[u8],
    sender_ratchet_key: &PublicKey,
    counter: u32,
    previous_counter: u32,
    ciphertext: &[u8],
    sender_identity_key: &PublicKey,
    receiver_identity_key: &PublicKey,
) -> Result<SignalMessage, SignalProtocolError> {
    SignalMessage::new(
        message_version,
        mac_key,
        *sender_ratchet_key,
        counter,
        previous_counter,
        ciphertext,
        &IdentityKey::new(*sender_identity_key),
        &IdentityKey::new(*receiver_identity_key),
    )
}

#[bridge_fn(ffi = "message_verify_mac")]
fn SignalMessage_VerifyMac(
    msg: &SignalMessage,
    sender_identity_key: &PublicKey,
    receiver_identity_key: &PublicKey,
    mac_key: &[u8],
) -> Result<bool, SignalProtocolError> {
    msg.verify_mac(
        &IdentityKey::new(*sender_identity_key),
        &IdentityKey::new(*receiver_identity_key),
        &mac_key,
    )
}

#[bridge_fn]
fn PreKeySignalMessage_New(
    message_version: u8,
    registration_id: u32,
    pre_key_id: Option<u32>,
    signed_pre_key_id: u32,
    base_key: &PublicKey,
    identity_key: &PublicKey,
    signal_message: &SignalMessage,
) -> Result<PreKeySignalMessage, SignalProtocolError> {
    PreKeySignalMessage::new(
        message_version,
        registration_id,
        pre_key_id,
        signed_pre_key_id,
        *base_key,
        IdentityKey::new(*identity_key),
        signal_message.clone(),
    )
}

bridge_deserialize!(PreKeySignalMessage::try_from);
bridge_get_bytearray!(Serialize(PreKeySignalMessage), jni = "PreKeySignalMessage_1GetSerialized" =>
    |m| Ok(m.serialized())
);
bridge_get_bytearray!(GetBaseKey(PreKeySignalMessage), ffi = false, node = false =>
    |m| Ok(m.base_key().serialize())
);
bridge_get_bytearray!(GetIdentityKey(PreKeySignalMessage), ffi = false, node = false =>
    |m| Ok(m.identity_key().serialize())
);
bridge_get_bytearray!(GetSignalMessage(PreKeySignalMessage), ffi = false, node = false =>
    |m| Ok(m.message().serialized())
);
bridge_get!(PreKeySignalMessage::registration_id -> u32);
bridge_get!(PreKeySignalMessage::signed_pre_key_id -> u32);
bridge_get!(PreKeySignalMessage::pre_key_id -> Option<u32>);
bridge_get!(PreKeySignalMessage::message_version as GetVersion -> u32);

bridge_deserialize!(SenderKeyMessage::try_from);
bridge_get_bytearray!(GetCipherText(SenderKeyMessage) => |m| Ok(m.ciphertext()));
bridge_get_bytearray!(Serialize(SenderKeyMessage), jni = "SenderKeyMessage_1GetSerialized" => |m| Ok(m.serialized()));
bridge_get!(SenderKeyMessage::key_id -> u32);
bridge_get!(SenderKeyMessage::iteration -> u32);

#[bridge_fn]
fn SenderKeyMessage_New(
    key_id: u32,
    iteration: u32,
    ciphertext: &[u8],
    pk: &PrivateKey,
) -> Result<SenderKeyMessage, SignalProtocolError> {
    let mut csprng = rand::rngs::OsRng;
    SenderKeyMessage::new(key_id, iteration, &ciphertext, &mut csprng, pk)
}

#[bridge_fn]
fn SenderKeyMessage_VerifySignature(
    skm: &SenderKeyMessage,
    pubkey: &PublicKey,
) -> Result<bool, SignalProtocolError> {
    skm.verify_signature(pubkey)
}

bridge_deserialize!(SenderKeyDistributionMessage::try_from);
bridge_get_bytearray!(GetChainKey(SenderKeyDistributionMessage) => SenderKeyDistributionMessage::chain_key);
bridge_get_bytearray!(GetSignatureKey(SenderKeyDistributionMessage), ffi = false, node = false =>
    |m| Ok(m.signing_key()?.serialize())
);
bridge_get_bytearray!(Serialize(SenderKeyDistributionMessage), jni = "SenderKeyDistributionMessage_1GetSerialized" =>
    |m| Ok(m.serialized())
);
bridge_get!(SenderKeyDistributionMessage::id -> u32);
bridge_get!(SenderKeyDistributionMessage::iteration -> u32);

#[bridge_fn]
fn SenderKeyDistributionMessage_New(
    key_id: u32,
    iteration: u32,
    chainkey: &[u8],
    pk: &PublicKey,
) -> Result<SenderKeyDistributionMessage, SignalProtocolError> {
    SenderKeyDistributionMessage::new(key_id, iteration, &chainkey, *pk)
}

#[bridge_fn]
fn PreKeyBundle_New(
    registration_id: u32,
    device_id: u32,
    prekey_id: Option<u32>,
    prekey: Option<&PublicKey>,
    signed_prekey_id: u32,
    signed_prekey: &PublicKey,
    signed_prekey_signature: &[u8],
    identity_key: &PublicKey,
) -> Result<PreKeyBundle, SignalProtocolError> {
    let identity_key = IdentityKey::new(*identity_key);

    let prekey = match (prekey, prekey_id) {
        (None, None) => None,
        (Some(k), Some(id)) => Some((id, *k)),
        _ => {
            return Err(SignalProtocolError::InvalidArgument(
                "Must supply both or neither of prekey and prekey_id".to_owned(),
            ))
        }
    };

    PreKeyBundle::new(
        registration_id,
        device_id,
        prekey,
        signed_prekey_id,
        *signed_prekey,
        signed_prekey_signature.to_vec(),
        identity_key,
    )
}

bridge_get_bytearray!(GetSignedPreKeySignature(PreKeyBundle) => PreKeyBundle::signed_pre_key_signature);
bridge_get!(PreKeyBundle::registration_id -> u32);
bridge_get!(PreKeyBundle::device_id -> u32);
bridge_get!(PreKeyBundle::signed_pre_key_id -> u32);
bridge_get!(PreKeyBundle::pre_key_id -> Option<u32>);
bridge_get!(PreKeyBundle::pre_key_public -> Option<PublicKey>);
bridge_get!(PreKeyBundle::signed_pre_key_public -> PublicKey);

bridge_deserialize!(SignedPreKeyRecord::deserialize);
bridge_get_bytearray!(GetSignature(SignedPreKeyRecord) => SignedPreKeyRecord::signature);
bridge_get_bytearray!(Serialize(SignedPreKeyRecord), jni = "SignedPreKeyRecord_1GetSerialized" =>
    SignedPreKeyRecord::serialize
);
bridge_get!(SignedPreKeyRecord::id -> u32);
bridge_get!(SignedPreKeyRecord::timestamp -> u64);
bridge_get!(SignedPreKeyRecord::public_key -> PublicKey);
bridge_get!(SignedPreKeyRecord::private_key -> PrivateKey);

#[bridge_fn]
fn SignedPreKeyRecord_New(
    id: u32,
    timestamp: u64,
    pub_key: &PublicKey,
    priv_key: &PrivateKey,
    signature: &[u8],
) -> SignedPreKeyRecord {
    let keypair = KeyPair::new(*pub_key, *priv_key);
    SignedPreKeyRecord::new(id, timestamp, &keypair, &signature)
}

bridge_deserialize!(PreKeyRecord::deserialize);
bridge_get_bytearray!(Serialize(PreKeyRecord), jni = "PreKeyRecord_1GetSerialized" =>
    PreKeyRecord::serialize
);
bridge_get!(PreKeyRecord::id -> u32);
bridge_get!(PreKeyRecord::public_key -> PublicKey);
bridge_get!(PreKeyRecord::private_key -> PrivateKey);

#[bridge_fn]
fn PreKeyRecord_New(id: u32, pub_key: &PublicKey, priv_key: &PrivateKey) -> PreKeyRecord {
    let keypair = KeyPair::new(*pub_key, *priv_key);
    PreKeyRecord::new(id, &keypair)
}

bridge_get!(SenderKeyName::group_id -> String);
bridge_get_string!(GetSenderName(SenderKeyName) => |skn| Ok(skn.sender()?.name().to_string()));

#[bridge_fn]
fn SenderKeyName_New(
    group_id: String,
    sender_name: String,
    sender_device_id: u32,
) -> Result<SenderKeyName, SignalProtocolError> {
    SenderKeyName::new(
        group_id,
        ProtocolAddress::new(sender_name, sender_device_id),
    )
}

bridge_deserialize!(SenderKeyRecord::deserialize);
bridge_get_bytearray!(Serialize(SenderKeyRecord), jni = "SenderKeyRecord_1GetSerialized" =>
    SenderKeyRecord::serialize
);

#[bridge_fn(ffi = "sender_key_record_new_fresh")]
fn SenderKeyRecord_New() -> SenderKeyRecord {
    SenderKeyRecord::new_empty()
}

bridge_deserialize!(ServerCertificate::deserialize);
bridge_get_bytearray!(GetSerialized(ServerCertificate) => ServerCertificate::serialized);
bridge_get_bytearray!(GetCertificate(ServerCertificate) => ServerCertificate::certificate);
bridge_get_bytearray!(GetSignature(ServerCertificate) => ServerCertificate::signature);
bridge_get!(ServerCertificate::key_id -> u32);
bridge_get!(ServerCertificate::public_key as GetKey -> PublicKey);

#[bridge_fn]
fn ServerCertificate_New(
    key_id: u32,
    server_key: &PublicKey,
    trust_root: &PrivateKey,
) -> Result<ServerCertificate, SignalProtocolError> {
    let mut rng = rand::rngs::OsRng;
    ServerCertificate::new(key_id, *server_key, trust_root, &mut rng)
}

bridge_deserialize!(SenderCertificate::deserialize);
bridge_get_bytearray!(GetSerialized(SenderCertificate) => SenderCertificate::serialized);
bridge_get_bytearray!(GetCertificate(SenderCertificate) => SenderCertificate::certificate);
bridge_get_bytearray!(GetSignature(SenderCertificate) => SenderCertificate::signature);
bridge_get!(SenderCertificate::sender_uuid -> Option<String>);
bridge_get!(SenderCertificate::sender_e164 -> Option<String>);
bridge_get!(SenderCertificate::expiration -> u64);
bridge_get!(SenderCertificate::sender_device_id as GetDeviceId -> u32);
bridge_get!(SenderCertificate::key -> PublicKey);

#[bridge_fn]
fn SenderCertificate_Validate(
    cert: &SenderCertificate,
    key: &PublicKey,
    time: u64,
) -> Result<bool, SignalProtocolError> {
    cert.validate(key, time)
}

#[bridge_fn]
fn SenderCertificate_New(
    sender_uuid: Option<String>,
    sender_e164: Option<String>,
    sender_device_id: u32,
    sender_key: &PublicKey,
    expiration: u64,
    signer_cert: &ServerCertificate,
    signer_key: &PrivateKey,
) -> Result<SenderCertificate, SignalProtocolError> {
    let mut rng = rand::rngs::OsRng;

    SenderCertificate::new(
        sender_uuid,
        sender_e164,
        *sender_key,
        sender_device_id,
        expiration,
        signer_cert.clone(),
        signer_key,
        &mut rng,
    )
}

bridge_deserialize!(UnidentifiedSenderMessageContent::deserialize);
bridge_get_bytearray!(
    Serialize(UnidentifiedSenderMessageContent),
    jni = "UnidentifiedSenderMessageContent_1GetSerialized" =>
    UnidentifiedSenderMessageContent::serialized
);
bridge_get_bytearray!(GetContents(UnidentifiedSenderMessageContent) =>
    UnidentifiedSenderMessageContent::contents
);

bridge_deserialize!(
    UnidentifiedSenderMessage::deserialize,
    ffi = false,
    node = false
);
bridge_get_bytearray!(GetSerialized(UnidentifiedSenderMessage), ffi = false, node = false =>
    UnidentifiedSenderMessage::serialized
);
bridge_get_bytearray!(GetEncryptedMessage(UnidentifiedSenderMessage), ffi = false, node = false =>
    UnidentifiedSenderMessage::encrypted_message
);
bridge_get_bytearray!(GetEncryptedStatic(UnidentifiedSenderMessage), ffi = false, node = false =>
    UnidentifiedSenderMessage::encrypted_static
);
bridge_get!(UnidentifiedSenderMessage::ephemeral_public -> PublicKey, ffi = false, node = false);

bridge_deserialize!(SessionRecord::deserialize);
bridge_get_bytearray!(Serialize(SessionRecord) => SessionRecord::serialize);
bridge_get_bytearray!(GetAliceBaseKey(SessionRecord), ffi = false, node = false =>
    |s| Ok(s.alice_base_key()?.to_vec())
);
bridge_get_bytearray!(GetLocalIdentityKeyPublic(SessionRecord), ffi = false, node = false =>
    SessionRecord::local_identity_key_bytes
);
bridge_get_optional_bytearray!(GetRemoteIdentityKeyPublic(SessionRecord), ffi = false, node = false =>
    SessionRecord::remote_identity_key_bytes
);
bridge_get!(SessionRecord::local_registration_id -> u32);
bridge_get!(SessionRecord::remote_registration_id -> u32);
bridge_get!(SessionRecord::has_sender_chain as HasSenderChain -> bool, ffi = false, node = false);
// Only needed for testing
bridge_get_bytearray!(GetSenderChainKeyValue(SessionRecord), ffi = false, node = false =>
    SessionRecord::get_sender_chain_key_bytes
);

#[bridge_fn]
fn Aes256GcmSiv_New(key: &[u8]) -> Result<Aes256GcmSiv, aes_gcm_siv::Error> {
    aes_gcm_siv::Aes256GcmSiv::new(&key)
}

#[bridge_fn_buffer]
fn Aes256GcmSiv_Encrypt<T: Env>(
    env: T,
    aes_gcm_siv: &Aes256GcmSiv,
    ptext: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
) -> Result<T::Buffer, aes_gcm_siv::Error> {
    let mut buf = Vec::with_capacity(ptext.len() + 16);
    buf.extend_from_slice(ptext);

    let gcm_tag = aes_gcm_siv.encrypt(&mut buf, &nonce, &associated_data)?;
    buf.extend_from_slice(&gcm_tag);

    Ok(env.buffer(buf))
}

#[bridge_fn_buffer]
fn Aes256GcmSiv_Decrypt<T: Env>(
    env: T,
    aes_gcm_siv: &Aes256GcmSiv,
    ctext: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
) -> Result<T::Buffer, aes_gcm_siv::Error> {
    let mut buf = ctext.to_vec();
    aes_gcm_siv.decrypt_with_appended_tag(&mut buf, &nonce, &associated_data)?;
    Ok(env.buffer(buf))
}
