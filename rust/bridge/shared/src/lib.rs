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

bridge_handle!(Aes256GcmSiv);
bridge_handle!(Fingerprint);
bridge_handle!(PreKeyBundle);
bridge_handle!(PreKeyRecord);
bridge_handle!(PreKeySignalMessage);
bridge_handle!(PrivateKey);
bridge_handle!(ProtocolAddress);
bridge_handle!(PublicKey);
bridge_handle!(SenderCertificate);
bridge_handle!(SenderKeyDistributionMessage);
bridge_handle!(SenderKeyMessage);
bridge_handle!(SenderKeyName);
bridge_handle!(SenderKeyRecord);
bridge_handle!(ServerCertificate);
bridge_handle!(SessionRecord);
bridge_handle!(SignalMessage);
bridge_handle!(SignedPreKeyRecord);
bridge_handle!(UnidentifiedSenderMessageContent);

bridge_destroy!(ProtocolAddress, ffi = address);
bridge_get_string!(name(ProtocolAddress), ffi = address_get_name =>
    |p| Ok(p.name())
);

#[bridge_fn(ffi = "address_new")]
fn ProtocolAddress_New(name: String, device_id: u32) -> ProtocolAddress {
    ProtocolAddress::new(name, device_id)
}

bridge_destroy!(PublicKey, ffi = publickey, jni = ECPublicKey);
bridge_deserialize!(PublicKey::deserialize, ffi = publickey, jni = None);
bridge_get_bytearray!(serialize(PublicKey), ffi = publickey_serialize, jni = ECPublicKey_1Serialize =>
    |k| Ok(k.serialize()));
bridge_get_bytearray!(
    get_public_key_bytes(PublicKey),
    ffi = publickey_get_public_key_bytes,
    jni = ECPublicKey_1GetPublicKeyBytes =>
    PublicKey::public_key_bytes
);

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

bridge_destroy!(PrivateKey, ffi = privatekey, jni = ECPrivateKey);
bridge_deserialize!(
    PrivateKey::deserialize,
    ffi = privatekey,
    jni = ECPrivateKey
);
bridge_get_bytearray!(
    serialize(PrivateKey),
    ffi = privatekey_serialize,
    jni = ECPrivateKey_1Serialize =>
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

bridge_destroy!(Fingerprint, jni = NumericFingerprintGenerator);
bridge_get_bytearray!(
    scannable_encoding(Fingerprint),
    jni = NumericFingerprintGenerator_1GetScannableEncoding =>
    |f| f.scannable.serialize()
);
bridge_get_string!(display_string(Fingerprint), jni = NumericFingerprintGenerator_1GetDisplayString =>
    Fingerprint::display_string
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

bridge_destroy!(SignalMessage, ffi = message);
bridge_deserialize!(SignalMessage::try_from, ffi = message);
bridge_get_bytearray!(get_sender_ratchet_key(SignalMessage), ffi = None =>
    |m| Ok(m.sender_ratchet_key().serialize())
);
bridge_get_bytearray!(get_body(SignalMessage), ffi = message_get_body =>
    |m| Ok(m.body())
);
bridge_get_bytearray!(get_serialized(SignalMessage), ffi = message_get_serialized =>
    |m| Ok(m.serialized())
);

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

bridge_destroy!(PreKeySignalMessage);
bridge_deserialize!(PreKeySignalMessage::try_from);
bridge_get_bytearray!(serialize(PreKeySignalMessage), jni = PreKeySignalMessage_1GetSerialized =>
    |m| Ok(m.serialized())
);
bridge_get_bytearray!(get_base_key(PreKeySignalMessage), ffi = None =>
    |m| Ok(m.base_key().serialize())
);
bridge_get_bytearray!(get_identity_key(PreKeySignalMessage), ffi = None =>
    |m| Ok(m.identity_key().serialize())
);
bridge_get_bytearray!(get_signal_message(PreKeySignalMessage), ffi = None =>
    |m| Ok(m.message().serialized())
);

bridge_destroy!(SenderKeyMessage);
bridge_deserialize!(SenderKeyMessage::try_from);
bridge_get_bytearray!(get_cipher_text(SenderKeyMessage) => |m| Ok(m.ciphertext()));
bridge_get_bytearray!(serialize(SenderKeyMessage), jni = SenderKeyMessage_1GetSerialized => |m| Ok(m.serialized()));

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

bridge_destroy!(SenderKeyDistributionMessage);
bridge_deserialize!(SenderKeyDistributionMessage::try_from);
bridge_get_bytearray!(get_chain_key(SenderKeyDistributionMessage) => SenderKeyDistributionMessage::chain_key);
bridge_get_bytearray!(get_signature_key(SenderKeyDistributionMessage), ffi = None =>
    |m| Ok(m.signing_key()?.serialize())
);
bridge_get_bytearray!(serialize(SenderKeyDistributionMessage), jni = SenderKeyDistributionMessage_1GetSerialized =>
    |m| Ok(m.serialized())
);

#[bridge_fn]
fn SenderKeyDistributionMessage_New(
    key_id: u32,
    iteration: u32,
    chainkey: &[u8],
    pk: &PublicKey,
) -> Result<SenderKeyDistributionMessage, SignalProtocolError> {
    SenderKeyDistributionMessage::new(key_id, iteration, &chainkey, *pk)
}

bridge_destroy!(PreKeyBundle);
bridge_get_bytearray!(get_signed_pre_key_signature(PreKeyBundle) => PreKeyBundle::signed_pre_key_signature);

bridge_destroy!(SignedPreKeyRecord);
bridge_deserialize!(SignedPreKeyRecord::deserialize);
bridge_get_bytearray!(get_signature(SignedPreKeyRecord) => SignedPreKeyRecord::signature);
bridge_get_bytearray!(serialize(SignedPreKeyRecord), jni = SignedPreKeyRecord_1GetSerialized =>
    SignedPreKeyRecord::serialize
);

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

bridge_destroy!(PreKeyRecord);
bridge_deserialize!(PreKeyRecord::deserialize);
bridge_get_bytearray!(serialize(PreKeyRecord), jni = PreKeyRecord_1GetSerialized =>
    PreKeyRecord::serialize
);

#[bridge_fn]
fn PreKeyRecord_New(id: u32, pub_key: &PublicKey, priv_key: &PrivateKey) -> PreKeyRecord {
    let keypair = KeyPair::new(*pub_key, *priv_key);
    PreKeyRecord::new(id, &keypair)
}

bridge_destroy!(SenderKeyName);
bridge_get_string!(get_group_id(SenderKeyName) => SenderKeyName::group_id);
bridge_get_string!(get_sender_name(SenderKeyName) => |skn| Ok(skn.sender()?.name().to_string()));

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

bridge_destroy!(SenderKeyRecord);
bridge_deserialize!(SenderKeyRecord::deserialize);
bridge_get_bytearray!(serialize(SenderKeyRecord), jni = SenderKeyRecord_1GetSerialized =>
    SenderKeyRecord::serialize
);

#[bridge_fn(ffi = "sender_key_record_new_fresh")]
fn SenderKeyRecord_New() -> SenderKeyRecord {
    SenderKeyRecord::new_empty()
}

bridge_destroy!(CiphertextMessage, jni = None);

bridge_destroy!(ServerCertificate);
bridge_deserialize!(ServerCertificate::deserialize);
bridge_get_bytearray!(get_serialized(ServerCertificate) => ServerCertificate::serialized);
bridge_get_bytearray!(get_certificate(ServerCertificate) => ServerCertificate::certificate);
bridge_get_bytearray!(get_signature(ServerCertificate) => ServerCertificate::signature);

#[bridge_fn]
fn ServerCertificate_New(
    key_id: u32,
    server_key: &PublicKey,
    trust_root: &PrivateKey,
) -> Result<ServerCertificate, SignalProtocolError> {
    let mut rng = rand::rngs::OsRng;
    ServerCertificate::new(key_id, *server_key, trust_root, &mut rng)
}

bridge_destroy!(SenderCertificate);
bridge_deserialize!(SenderCertificate::deserialize);
bridge_get_bytearray!(get_serialized(SenderCertificate) => SenderCertificate::serialized);
bridge_get_bytearray!(get_certificate(SenderCertificate) => SenderCertificate::certificate);
bridge_get_bytearray!(get_signature(SenderCertificate) => SenderCertificate::signature);
bridge_get_optional_string!(get_sender_uuid(SenderCertificate) => SenderCertificate::sender_uuid);
bridge_get_optional_string!(get_sender_e164(SenderCertificate) => SenderCertificate::sender_e164);

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

bridge_destroy!(UnidentifiedSenderMessageContent);
bridge_deserialize!(UnidentifiedSenderMessageContent::deserialize);
bridge_get_bytearray!(
    serialize(UnidentifiedSenderMessageContent),
    jni = UnidentifiedSenderMessageContent_1GetSerialized =>
    UnidentifiedSenderMessageContent::serialized
);
bridge_get_bytearray!(get_contents(UnidentifiedSenderMessageContent) =>
    UnidentifiedSenderMessageContent::contents
);

bridge_destroy!(UnidentifiedSenderMessage, ffi = None, node = None);
bridge_deserialize!(
    UnidentifiedSenderMessage::deserialize,
    ffi = None,
    node = None
);
bridge_get_bytearray!(get_serialized(UnidentifiedSenderMessage), ffi = None, node = None =>
    UnidentifiedSenderMessage::serialized
);
bridge_get_bytearray!(get_encrypted_message(UnidentifiedSenderMessage), ffi = None, node = None =>
    UnidentifiedSenderMessage::encrypted_message
);
bridge_get_bytearray!(get_encrypted_static(UnidentifiedSenderMessage), ffi = None, node = None =>
    UnidentifiedSenderMessage::encrypted_static
);

bridge_destroy!(SessionRecord);
bridge_deserialize!(SessionRecord::deserialize);
bridge_get_bytearray!(serialize(SessionRecord) => SessionRecord::serialize);
bridge_get_bytearray!(get_alice_base_key(SessionRecord), ffi = None =>
    |s| Ok(s.alice_base_key()?.to_vec())
);
bridge_get_bytearray!(get_local_identity_key_public(SessionRecord), ffi = None =>
    SessionRecord::local_identity_key_bytes
);
bridge_get_optional_bytearray!(get_remote_identity_key_public(SessionRecord), ffi = None =>
    SessionRecord::remote_identity_key_bytes
);
// Only needed for testing
bridge_get_bytearray!(get_sender_chain_key_value(SessionRecord), ffi = None =>
    SessionRecord::get_sender_chain_key_bytes
);

bridge_destroy!(Aes256GcmSiv);

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
