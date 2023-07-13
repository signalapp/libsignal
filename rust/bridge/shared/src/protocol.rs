//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;
use libsignal_protocol::error::Result;
use libsignal_protocol::*;
use static_assertions::const_assert_eq;
use std::convert::TryFrom;
use uuid::Uuid;

// Will be unused when building for Node only.
#[allow(unused_imports)]
use futures_util::FutureExt;

use crate::support::*;
use crate::*;

#[allow(dead_code)]
const KYBER_KEY_TYPE: kem::KeyType = kem::KeyType::Kyber1024;

pub type KyberKeyPair = kem::KeyPair;
pub type KyberPublicKey = kem::PublicKey;
pub type KyberSecretKey = kem::SecretKey;

bridge_handle!(CiphertextMessage, clone = false, jni = false);
bridge_handle!(DecryptionErrorMessage);
bridge_handle!(Fingerprint, jni = NumericFingerprintGenerator);
bridge_handle!(PlaintextContent);
bridge_handle!(PreKeyBundle);
bridge_handle!(PreKeyRecord);
bridge_handle!(PreKeySignalMessage);
bridge_handle!(PrivateKey, ffi = privatekey, jni = ECPrivateKey);
bridge_handle!(ProtocolAddress, ffi = address);
bridge_handle!(PublicKey, ffi = publickey, jni = ECPublicKey);
bridge_handle!(SenderCertificate);
bridge_handle!(SenderKeyDistributionMessage);
bridge_handle!(SenderKeyMessage);
bridge_handle!(SenderKeyRecord);
bridge_handle!(ServerCertificate);
bridge_handle!(SessionRecord, mut = true);
bridge_handle!(SignalMessage, ffi = message);
bridge_handle!(SignedPreKeyRecord);
bridge_handle!(KyberPreKeyRecord);
bridge_handle!(UnidentifiedSenderMessageContent, clone = false);
bridge_handle!(SealedSenderDecryptionResult, ffi = false, jni = false);
bridge_handle!(KyberKeyPair);
bridge_handle!(KyberPublicKey);
bridge_handle!(KyberSecretKey);

#[derive(Clone, Copy, Debug)]
pub(crate) struct Timestamp(u64);

impl Timestamp {
    pub(crate) fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    pub(crate) fn as_millis(self) -> u64 {
        self.0
    }
}

impl From<u64> for Timestamp {
    fn from(value: u64) -> Self {
        Self::from_millis(value)
    }
}

#[bridge_fn(ffi = false)]
fn HKDF_DeriveSecrets(
    output_length: u32,
    ikm: &[u8],
    label: Option<&[u8]>,
    salt: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let label = label.unwrap_or(&[]);
    let mut buffer = vec![0; output_length as usize];
    hkdf::Hkdf::<sha2::Sha256>::new(salt, ikm)
        .expand(label, &mut buffer)
        .map_err(|_| {
            SignalProtocolError::InvalidArgument(format!("output too long ({})", output_length))
        })?;
    Ok(buffer)
}

// Alternate implementation to fill an existing buffer.
#[bridge_fn_void(jni = false, node = false)]
fn HKDF_Derive(output: &mut [u8], ikm: &[u8], label: &[u8], salt: &[u8]) -> Result<()> {
    hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm)
        .expand(label, output)
        .map_err(|_| {
            SignalProtocolError::InvalidArgument(format!("output too long ({})", output.len()))
        })?;
    Ok(())
}

// FIXME: Use bridge_get! when it works on values instead of references.
#[bridge_fn]
fn ServiceId_ServiceIdBinary(value: ServiceId) -> Vec<u8> {
    value.service_id_binary()
}

// FIXME: Use bridge_get! when it works on values instead of references.
#[bridge_fn]
fn ServiceId_ServiceIdString(value: ServiceId) -> String {
    value.service_id_string()
}

#[bridge_fn]
fn ServiceId_ServiceIdLog(value: ServiceId) -> String {
    format!("{value:?}")
}

#[bridge_fn]
fn ServiceId_ParseFromServiceIdBinary(input: &[u8]) -> Result<ServiceId> {
    ServiceId::parse_from_service_id_binary(input).ok_or_else(|| {
        SignalProtocolError::InvalidArgument("invalid Service-Id-Binary".to_string())
    })
}

// FIXME: use &str
#[bridge_fn]
fn ServiceId_ParseFromServiceIdString(input: String) -> Result<ServiceId> {
    ServiceId::parse_from_service_id_string(&input).ok_or_else(|| {
        SignalProtocolError::InvalidArgument("invalid Service-Id-String".to_string())
    })
}

#[bridge_fn(ffi = "address_new")]
fn ProtocolAddress_New(name: String, device_id: u32) -> ProtocolAddress {
    ProtocolAddress::new(name, device_id.into())
}

#[bridge_fn(ffi = "publickey_deserialize", jni = false)]
fn PublicKey_Deserialize(data: &[u8]) -> Result<PublicKey> {
    PublicKey::deserialize(data)
}

// Alternate implementation to deserialize from an offset.
#[bridge_fn(ffi = false, node = false)]
fn ECPublicKey_Deserialize(data: &[u8], offset: u32) -> Result<PublicKey> {
    let offset = offset as usize;
    PublicKey::deserialize(&data[offset..])
}

bridge_get!(
    PublicKey::serialize as Serialize -> Vec<u8>,
    ffi = "publickey_serialize",
    jni = "ECPublicKey_1Serialize"
);
bridge_get!(
    PublicKey::public_key_bytes -> &[u8],
    ffi = "publickey_get_public_key_bytes",
    jni = "ECPublicKey_1GetPublicKeyBytes"
);
bridge_get!(ProtocolAddress::device_id as DeviceId -> u32, ffi = "address_get_device_id");
bridge_get!(ProtocolAddress::name as Name -> &str, ffi = "address_get_name");

#[bridge_fn(ffi = "publickey_equals", node = "PublicKey_Equals")]
fn ECPublicKey_Equals(lhs: &PublicKey, rhs: &PublicKey) -> bool {
    lhs == rhs
}

#[bridge_fn(ffi = "publickey_compare", node = "PublicKey_Compare")]
fn ECPublicKey_Compare(key1: &PublicKey, key2: &PublicKey) -> i32 {
    match key1.cmp(key2) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

#[bridge_fn(ffi = "publickey_verify", node = "PublicKey_Verify")]
fn ECPublicKey_Verify(key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
    key.verify_signature(message, signature)
}

#[bridge_fn(ffi = "privatekey_deserialize", jni = "ECPrivateKey_1Deserialize")]
fn PrivateKey_Deserialize(data: &[u8]) -> Result<PrivateKey> {
    PrivateKey::deserialize(data)
}

bridge_get!(
    PrivateKey::serialize as Serialize -> Vec<u8>,
    ffi = "privatekey_serialize",
    jni = "ECPrivateKey_1Serialize"
);

#[bridge_fn(ffi = "privatekey_generate", node = "PrivateKey_Generate")]
fn ECPrivateKey_Generate() -> PrivateKey {
    let mut rng = rand::rngs::OsRng;
    let keypair = KeyPair::generate(&mut rng);
    keypair.private_key
}

#[bridge_fn(ffi = "privatekey_get_public_key", node = "PrivateKey_GetPublicKey")]
fn ECPrivateKey_GetPublicKey(k: &PrivateKey) -> Result<PublicKey> {
    k.public_key()
}

#[bridge_fn(ffi = "privatekey_sign", node = "PrivateKey_Sign")]
fn ECPrivateKey_Sign(key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>> {
    let mut rng = rand::rngs::OsRng;
    Ok(key.calculate_signature(message, &mut rng)?.into_vec())
}

#[bridge_fn(ffi = "privatekey_agree", node = "PrivateKey_Agree")]
fn ECPrivateKey_Agree(private_key: &PrivateKey, public_key: &PublicKey) -> Result<Vec<u8>> {
    Ok(private_key.calculate_agreement(public_key)?.into_vec())
}

bridge_get!(
    KyberPublicKey::serialize as Serialize -> Vec<u8>,
    jni = "KyberPublicKey_1Serialize"
);

#[bridge_fn(jni = false)]
fn KyberPublicKey_Deserialize(data: &[u8]) -> Result<KyberPublicKey> {
    KyberPublicKey::deserialize(data)
}

#[bridge_fn(ffi = false, node = false)]
fn KyberPublicKey_DeserializeWithOffset(data: &[u8], offset: u32) -> Result<KyberPublicKey> {
    let offset = offset as usize;
    KyberPublicKey::deserialize(&data[offset..])
}

bridge_get!(
    KyberSecretKey::serialize as Serialize -> Vec<u8>,
    jni = "KyberSecretKey_1Serialize"
);

#[bridge_fn(jni = "KyberSecretKey_1Deserialize")]
fn KyberSecretKey_Deserialize(data: &[u8]) -> Result<KyberSecretKey> {
    KyberSecretKey::deserialize(data)
}

#[bridge_fn]
fn KyberPublicKey_Equals(lhs: &KyberPublicKey, rhs: &KyberPublicKey) -> bool {
    lhs == rhs
}

#[bridge_fn]
fn KyberKeyPair_Generate() -> KyberKeyPair {
    KyberKeyPair::generate(KYBER_KEY_TYPE)
}

#[bridge_fn]
fn KyberKeyPair_GetPublicKey(key_pair: &KyberKeyPair) -> KyberPublicKey {
    key_pair.public_key.clone()
}

#[bridge_fn]
fn KyberKeyPair_GetSecretKey(key_pair: &KyberKeyPair) -> KyberSecretKey {
    key_pair.secret_key.clone()
}

#[bridge_fn(ffi = "identitykeypair_serialize")]
fn IdentityKeyPair_Serialize(public_key: &PublicKey, private_key: &PrivateKey) -> Vec<u8> {
    let identity_key_pair = IdentityKeyPair::new(IdentityKey::new(*public_key), *private_key);
    identity_key_pair.serialize().into_vec()
}

#[bridge_fn(ffi = "identitykeypair_sign_alternate_identity")]
fn IdentityKeyPair_SignAlternateIdentity(
    public_key: &PublicKey,
    private_key: &PrivateKey,
    other_identity: &PublicKey,
) -> Result<Vec<u8>> {
    let mut rng = rand::rngs::OsRng;
    let identity_key_pair = IdentityKeyPair::new(IdentityKey::new(*public_key), *private_key);
    let other_identity = IdentityKey::new(*other_identity);
    Ok(identity_key_pair
        .sign_alternate_identity(&other_identity, &mut rng)?
        .into_vec())
}

#[bridge_fn(ffi = "identitykey_verify_alternate_identity")]
fn IdentityKey_VerifyAlternateIdentity(
    public_key: &PublicKey,
    other_identity: &PublicKey,
    signature: &[u8],
) -> Result<bool> {
    let identity = IdentityKey::new(*public_key);
    let other_identity = IdentityKey::new(*other_identity);
    identity.verify_alternate_identity(&other_identity, signature)
}

#[bridge_fn(jni = false)]
fn Fingerprint_New(
    iterations: u32,
    version: u32,
    local_identifier: &[u8],
    local_key: &PublicKey,
    remote_identifier: &[u8],
    remote_key: &PublicKey,
) -> Result<Fingerprint> {
    Fingerprint::new(
        version,
        iterations,
        local_identifier,
        &IdentityKey::new(*local_key),
        remote_identifier,
        &IdentityKey::new(*remote_key),
    )
}

// Alternate implementation that takes untyped buffers.
#[bridge_fn(ffi = false, node = false)]
fn NumericFingerprintGenerator_New(
    iterations: u32,
    version: u32,
    local_identifier: &[u8],
    local_key: &[u8],
    remote_identifier: &[u8],
    remote_key: &[u8],
) -> Result<Fingerprint> {
    let local_key = IdentityKey::decode(local_key)?;
    let remote_key = IdentityKey::decode(remote_key)?;

    Fingerprint::new(
        version,
        iterations,
        local_identifier,
        &local_key,
        remote_identifier,
        &remote_key,
    )
}

#[bridge_fn(jni = "NumericFingerprintGenerator_1GetScannableEncoding")]
fn Fingerprint_ScannableEncoding(obj: &Fingerprint) -> Result<Vec<u8>> {
    obj.scannable.serialize()
}

bridge_get!(
    Fingerprint::display_string as DisplayString -> String,
    jni = "NumericFingerprintGenerator_1GetDisplayString"
);

#[bridge_fn(ffi = "fingerprint_compare")]
fn ScannableFingerprint_Compare(fprint1: &[u8], fprint2: &[u8]) -> Result<bool> {
    ScannableFingerprint::deserialize(fprint1)?.compare(fprint2)
}

#[bridge_fn(ffi = "message_deserialize")]
fn SignalMessage_Deserialize(data: &[u8]) -> Result<SignalMessage> {
    SignalMessage::try_from(data)
}

bridge_get!(SignalMessage::body -> &[u8], ffi = "message_get_body");
bridge_get!(SignalMessage::serialized -> &[u8], ffi = "message_get_serialized");
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
) -> Result<SignalMessage> {
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
) -> Result<bool> {
    msg.verify_mac(
        &IdentityKey::new(*sender_identity_key),
        &IdentityKey::new(*receiver_identity_key),
        mac_key,
    )
}

#[bridge_fn(ffi = "message_get_sender_ratchet_key", node = false)]
fn SignalMessage_GetSenderRatchetKey(m: &SignalMessage) -> PublicKey {
    *m.sender_ratchet_key()
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
) -> Result<PreKeySignalMessage> {
    PreKeySignalMessage::new(
        message_version,
        registration_id,
        pre_key_id.map(|id| id.into()),
        signed_pre_key_id.into(),
        None, // TODO: accept kyber payload
        *base_key,
        IdentityKey::new(*identity_key),
        signal_message.clone(),
    )
}

#[bridge_fn(node = false)]
fn PreKeySignalMessage_GetBaseKey(m: &PreKeySignalMessage) -> PublicKey {
    *m.base_key()
}

#[bridge_fn(node = false)]
fn PreKeySignalMessage_GetIdentityKey(m: &PreKeySignalMessage) -> PublicKey {
    *m.identity_key().public_key()
}

#[bridge_fn(node = false)]
fn PreKeySignalMessage_GetSignalMessage(m: &PreKeySignalMessage) -> SignalMessage {
    m.message().clone()
}

bridge_deserialize!(PreKeySignalMessage::try_from);
bridge_get!(
    PreKeySignalMessage::serialized as Serialize -> &[u8],
    jni = "PreKeySignalMessage_1GetSerialized"
);

bridge_get!(PreKeySignalMessage::registration_id -> u32);
bridge_get!(PreKeySignalMessage::signed_pre_key_id -> u32);
bridge_get!(PreKeySignalMessage::pre_key_id -> Option<u32>);
bridge_get!(PreKeySignalMessage::message_version as GetVersion -> u32);

bridge_deserialize!(SenderKeyMessage::try_from);
bridge_get!(SenderKeyMessage::ciphertext as GetCipherText -> &[u8]);
bridge_get!(
    SenderKeyMessage::serialized as Serialize -> &[u8],
    jni = "SenderKeyMessage_1GetSerialized"
);
bridge_get!(SenderKeyMessage::distribution_id -> Uuid);
bridge_get!(SenderKeyMessage::chain_id -> u32);
bridge_get!(SenderKeyMessage::iteration -> u32);

// For testing
#[bridge_fn]
fn SenderKeyMessage_New(
    message_version: u8,
    distribution_id: Uuid,
    chain_id: u32,
    iteration: u32,
    ciphertext: &[u8],
    pk: &PrivateKey,
) -> Result<SenderKeyMessage> {
    let mut csprng = rand::rngs::OsRng;
    SenderKeyMessage::new(
        message_version,
        distribution_id,
        chain_id,
        iteration,
        ciphertext.into(),
        &mut csprng,
        pk,
    )
}

#[bridge_fn]
fn SenderKeyMessage_VerifySignature(skm: &SenderKeyMessage, pubkey: &PublicKey) -> Result<bool> {
    skm.verify_signature(pubkey)
}

bridge_deserialize!(SenderKeyDistributionMessage::try_from);
bridge_get!(SenderKeyDistributionMessage::chain_key -> &[u8]);

bridge_get!(
    SenderKeyDistributionMessage::serialized as Serialize -> &[u8],
    jni = "SenderKeyDistributionMessage_1GetSerialized"
);
bridge_get!(SenderKeyDistributionMessage::distribution_id -> Uuid);
bridge_get!(SenderKeyDistributionMessage::chain_id -> u32);
bridge_get!(SenderKeyDistributionMessage::iteration -> u32);

// For testing
#[bridge_fn]
fn SenderKeyDistributionMessage_New(
    message_version: u8,
    distribution_id: Uuid,
    chain_id: u32,
    iteration: u32,
    chainkey: &[u8],
    pk: &PublicKey,
) -> Result<SenderKeyDistributionMessage> {
    SenderKeyDistributionMessage::new(
        message_version,
        distribution_id,
        chain_id,
        iteration,
        chainkey.into(),
        *pk,
    )
}

#[bridge_fn(node = false)]
fn SenderKeyDistributionMessage_GetSignatureKey(
    m: &SenderKeyDistributionMessage,
) -> Result<PublicKey> {
    Ok(*m.signing_key()?)
}

bridge_deserialize!(DecryptionErrorMessage::try_from);
bridge_get!(DecryptionErrorMessage::timestamp -> Timestamp);
bridge_get!(DecryptionErrorMessage::device_id -> u32);
bridge_get!(
    DecryptionErrorMessage::serialized as Serialize -> &[u8],
    jni = "DecryptionErrorMessage_1GetSerialized"
);

#[bridge_fn]
fn DecryptionErrorMessage_GetRatchetKey(m: &DecryptionErrorMessage) -> Option<PublicKey> {
    m.ratchet_key().cloned()
}

#[bridge_fn]
fn DecryptionErrorMessage_ForOriginalMessage(
    original_bytes: &[u8],
    original_type: u8,
    original_timestamp: Timestamp,
    original_sender_device_id: u32,
) -> Result<DecryptionErrorMessage> {
    let original_type = CiphertextMessageType::try_from(original_type).map_err(|_| {
        SignalProtocolError::InvalidArgument(format!("unknown message type {}", original_type))
    })?;
    DecryptionErrorMessage::for_original(
        original_bytes,
        original_type,
        original_timestamp.as_millis(),
        original_sender_device_id,
    )
}

#[bridge_fn]
fn DecryptionErrorMessage_ExtractFromSerializedContent(
    bytes: &[u8],
) -> Result<DecryptionErrorMessage> {
    extract_decryption_error_message_from_serialized_content(bytes)
}

bridge_deserialize!(PlaintextContent::try_from);
bridge_get!(
    PlaintextContent::serialized as Serialize -> &[u8],
    jni = "PlaintextContent_1GetSerialized"
);
bridge_get!(PlaintextContent::body -> &[u8]);

#[bridge_fn]
fn PlaintextContent_FromDecryptionErrorMessage(m: &DecryptionErrorMessage) -> PlaintextContent {
    PlaintextContent::from(m.clone())
}

/// Save an allocation by decrypting all in one go.
///
/// Only useful for APIs that *do* decrypt all in one go, which is currently just Java.
#[bridge_fn(ffi = false, node = false)]
fn PlaintextContent_DeserializeAndGetContent(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(PlaintextContent::try_from(bytes)?.body().to_vec())
}

#[allow(clippy::too_many_arguments)]
#[bridge_fn(jni = "PreKeyBundle_1New")]
fn PreKeyBundle_New(
    registration_id: u32,
    device_id: u32,
    prekey_id: Option<u32>,
    prekey: Option<&PublicKey>,
    signed_prekey_id: u32,
    signed_prekey: &PublicKey,
    signed_prekey_signature: &[u8],
    identity_key: &PublicKey,
    kyber_prekey_id: Option<u32>,
    kyber_prekey: Option<&KyberPublicKey>,
    kyber_prekey_signature: &[u8],
) -> Result<PreKeyBundle> {
    let identity_key = IdentityKey::new(*identity_key);

    let prekey: Option<(PreKeyId, PublicKey)> = match (prekey, prekey_id) {
        (None, None) => None,
        (Some(k), Some(id)) => Some((id.into(), *k)),
        _ => {
            return Err(SignalProtocolError::InvalidArgument(
                "Must supply both or neither of prekey and prekey_id".to_owned(),
            ));
        }
    };

    let bundle = PreKeyBundle::new(
        registration_id,
        device_id.into(),
        prekey,
        signed_prekey_id.into(),
        *signed_prekey,
        signed_prekey_signature.to_vec(),
        identity_key,
    )?;
    match (kyber_prekey_id, kyber_prekey, kyber_prekey_signature) {
        (Some(id), Some(public), signature) if !signature.is_empty() => {
            Ok(bundle.with_kyber_pre_key(id.into(), public.clone(), signature.to_vec()))
        }
        (None, None, &[]) => Ok(bundle),
        _ => Err(SignalProtocolError::InvalidArgument(
            "All or none Kyber pre key arguments must be set".to_owned(),
        )),
    }
}

#[bridge_fn]
fn PreKeyBundle_GetIdentityKey(p: &PreKeyBundle) -> Result<PublicKey> {
    Ok(*p.identity_key()?.public_key())
}

bridge_get!(PreKeyBundle::signed_pre_key_signature -> &[u8]);
bridge_get!(PreKeyBundle::registration_id -> u32);
bridge_get!(PreKeyBundle::device_id -> u32);
bridge_get!(PreKeyBundle::signed_pre_key_id -> u32);
bridge_get!(PreKeyBundle::pre_key_id -> Option<u32>);
bridge_get!(PreKeyBundle::pre_key_public -> Option<PublicKey>);
bridge_get!(PreKeyBundle::signed_pre_key_public -> PublicKey);
bridge_get!(PreKeyBundle::kyber_pre_key_id -> Option<u32>, ffi = false);
#[bridge_fn]
fn PreKeyBundle_GetKyberPreKeyPublic(bundle: &PreKeyBundle) -> Result<Option<KyberPublicKey>> {
    bundle
        .kyber_pre_key_public()
        .map(|maybe_key| maybe_key.cloned())
}

#[bridge_fn]
fn PreKeyBundle_GetKyberPreKeySignature(bundle: &PreKeyBundle) -> Result<&[u8]> {
    bundle
        .kyber_pre_key_signature()
        .map(|maybe_sig| maybe_sig.unwrap_or(&[]))
}

bridge_deserialize!(SignedPreKeyRecord::deserialize);
bridge_get!(SignedPreKeyRecord::signature -> Vec<u8>);
bridge_get!(
    SignedPreKeyRecord::serialize as Serialize -> Vec<u8>,
    jni = "SignedPreKeyRecord_1GetSerialized"
);
bridge_get!(SignedPreKeyRecord::id -> u32);
bridge_get!(SignedPreKeyRecord::timestamp -> Timestamp);
bridge_get!(SignedPreKeyRecord::public_key -> PublicKey);
bridge_get!(SignedPreKeyRecord::private_key -> PrivateKey);

bridge_deserialize!(KyberPreKeyRecord::deserialize);
bridge_get!(KyberPreKeyRecord::signature -> Vec<u8>);
bridge_get!(
    KyberPreKeyRecord::serialize as Serialize -> Vec<u8>,
    jni = "KyberPreKeyRecord_1GetSerialized"
);
bridge_get!(KyberPreKeyRecord::id -> u32);
bridge_get!(KyberPreKeyRecord::timestamp -> Timestamp);
bridge_get!(KyberPreKeyRecord::public_key -> KyberPublicKey);
bridge_get!(KyberPreKeyRecord::secret_key -> KyberSecretKey);
bridge_get!(KyberPreKeyRecord::key_pair -> KyberKeyPair);

#[bridge_fn]
fn SignedPreKeyRecord_New(
    id: u32,
    timestamp: Timestamp,
    pub_key: &PublicKey,
    priv_key: &PrivateKey,
    signature: &[u8],
) -> SignedPreKeyRecord {
    let keypair = KeyPair::new(*pub_key, *priv_key);
    SignedPreKeyRecord::new(id.into(), timestamp.as_millis(), &keypair, signature)
}

#[bridge_fn]
fn KyberPreKeyRecord_New(
    id: u32,
    timestamp: Timestamp,
    key_pair: &KyberKeyPair,
    signature: &[u8],
) -> KyberPreKeyRecord {
    KyberPreKeyRecord::new(id.into(), timestamp.as_millis(), key_pair, signature)
}

bridge_deserialize!(PreKeyRecord::deserialize);
bridge_get!(
    PreKeyRecord::serialize as Serialize -> Vec<u8>,
    jni = "PreKeyRecord_1GetSerialized"
);
bridge_get!(PreKeyRecord::id -> u32);
bridge_get!(PreKeyRecord::public_key -> PublicKey);
bridge_get!(PreKeyRecord::private_key -> PrivateKey);

#[bridge_fn]
fn PreKeyRecord_New(id: u32, pub_key: &PublicKey, priv_key: &PrivateKey) -> PreKeyRecord {
    let keypair = KeyPair::new(*pub_key, *priv_key);
    PreKeyRecord::new(id.into(), &keypair)
}

bridge_deserialize!(SenderKeyRecord::deserialize);
bridge_get!(
    SenderKeyRecord::serialize as Serialize -> Vec<u8>,
    jni = "SenderKeyRecord_1GetSerialized"
);

bridge_deserialize!(ServerCertificate::deserialize);
bridge_get!(ServerCertificate::serialized -> &[u8]);
bridge_get!(ServerCertificate::certificate -> &[u8]);
bridge_get!(ServerCertificate::signature -> &[u8]);
bridge_get!(ServerCertificate::key_id -> u32);
bridge_get!(ServerCertificate::public_key as GetKey -> PublicKey);

#[bridge_fn]
fn ServerCertificate_New(
    key_id: u32,
    server_key: &PublicKey,
    trust_root: &PrivateKey,
) -> Result<ServerCertificate> {
    let mut rng = rand::rngs::OsRng;
    ServerCertificate::new(key_id, *server_key, trust_root, &mut rng)
}

bridge_deserialize!(SenderCertificate::deserialize);
bridge_get!(SenderCertificate::serialized -> &[u8]);
bridge_get!(SenderCertificate::certificate -> &[u8]);
bridge_get!(SenderCertificate::signature -> &[u8]);
bridge_get!(SenderCertificate::sender_uuid -> &str);
bridge_get!(SenderCertificate::sender_e164 -> Option<&str>);
bridge_get!(SenderCertificate::expiration -> Timestamp);
bridge_get!(SenderCertificate::sender_device_id as GetDeviceId -> u32);
bridge_get!(SenderCertificate::key -> PublicKey);

#[bridge_fn]
fn SenderCertificate_Validate(
    cert: &SenderCertificate,
    key: &PublicKey,
    time: Timestamp,
) -> Result<bool> {
    cert.validate(key, time.as_millis())
}

#[bridge_fn]
fn SenderCertificate_GetServerCertificate(cert: &SenderCertificate) -> Result<ServerCertificate> {
    Ok(cert.signer()?.clone())
}

#[bridge_fn]
fn SenderCertificate_New(
    sender_uuid: String,
    sender_e164: Option<String>,
    sender_device_id: u32,
    sender_key: &PublicKey,
    expiration: Timestamp,
    signer_cert: &ServerCertificate,
    signer_key: &PrivateKey,
) -> Result<SenderCertificate> {
    let mut rng = rand::rngs::OsRng;

    SenderCertificate::new(
        sender_uuid,
        sender_e164,
        *sender_key,
        sender_device_id.into(),
        expiration.as_millis(),
        signer_cert.clone(),
        signer_key,
        &mut rng,
    )
}

bridge_deserialize!(UnidentifiedSenderMessageContent::deserialize);
bridge_get!(
    UnidentifiedSenderMessageContent::serialized as Serialize -> &[u8],
    jni = "UnidentifiedSenderMessageContent_1GetSerialized"
);
bridge_get!(UnidentifiedSenderMessageContent::contents -> &[u8]);
bridge_get!(UnidentifiedSenderMessageContent::group_id -> Option<&[u8]>, ffi = false);

#[bridge_fn(jni = false, node = false)]
fn UnidentifiedSenderMessageContent_GetGroupIdOrEmpty(
    m: &UnidentifiedSenderMessageContent,
) -> Result<&[u8]> {
    Ok(m.group_id()?.unwrap_or_default())
}

#[bridge_fn]
fn UnidentifiedSenderMessageContent_GetSenderCert(
    m: &UnidentifiedSenderMessageContent,
) -> Result<SenderCertificate> {
    Ok(m.sender()?.clone())
}

#[bridge_fn]
fn UnidentifiedSenderMessageContent_GetMsgType(m: &UnidentifiedSenderMessageContent) -> Result<u8> {
    Ok(m.msg_type()? as u8)
}

#[derive(Debug)]
#[repr(C)]
pub enum FfiContentHint {
    Default = 0,
    Resendable = 1,
    Implicit = 2,
}

const_assert_eq!(
    FfiContentHint::Default as u32,
    ContentHint::Default.to_u32(),
);
const_assert_eq!(
    FfiContentHint::Resendable as u32,
    ContentHint::Resendable.to_u32(),
);
const_assert_eq!(
    FfiContentHint::Implicit as u32,
    ContentHint::Implicit.to_u32()
);

#[bridge_fn]
fn UnidentifiedSenderMessageContent_GetContentHint(
    m: &UnidentifiedSenderMessageContent,
) -> Result<u32> {
    Ok(m.content_hint()?.into())
}

#[bridge_fn(ffi = false, jni = false)]
fn UnidentifiedSenderMessageContent_New(
    message: &CiphertextMessage,
    sender: &SenderCertificate,
    content_hint: u32,
    group_id: Option<&[u8]>,
) -> Result<UnidentifiedSenderMessageContent> {
    UnidentifiedSenderMessageContent::new(
        message.message_type(),
        sender.clone(),
        message.serialize().to_owned(),
        ContentHint::from(content_hint),
        group_id.map(|g| g.to_owned()),
    )
}

// Alternate version for FFI because FFI can't support optional slices.
#[bridge_fn(jni = false, node = false)]
fn UnidentifiedSenderMessageContentNew(
    message: &CiphertextMessage,
    sender: &SenderCertificate,
    content_hint: u32,
    group_id: &[u8],
) -> Result<UnidentifiedSenderMessageContent> {
    UnidentifiedSenderMessageContent::new(
        message.message_type(),
        sender.clone(),
        message.serialize().to_owned(),
        ContentHint::from(content_hint),
        if group_id.is_empty() {
            None
        } else {
            Some(group_id.to_owned())
        },
    )
}

// Alternate version for Java since CiphertextMessage isn't opaque in Java.
#[bridge_fn(
    ffi = false,
    jni = "UnidentifiedSenderMessageContent_1New",
    node = false
)]
fn UnidentifiedSenderMessageContent_New_Java(
    message: jni::CiphertextMessageRef,
    sender: &SenderCertificate,
    content_hint: u32,
    group_id: Option<&[u8]>,
) -> Result<UnidentifiedSenderMessageContent> {
    UnidentifiedSenderMessageContent::new(
        message.message_type(),
        sender.clone(),
        message.serialize().to_owned(),
        ContentHint::from(content_hint),
        group_id.map(|g| g.to_owned()),
    )
}

#[derive(Debug)]
#[repr(C)]
pub enum FfiCiphertextMessageType {
    Whisper = 2,
    PreKey = 3,
    SenderKey = 7,
    Plaintext = 8,
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
    FfiCiphertextMessageType::Plaintext as u8,
    CiphertextMessageType::Plaintext as u8
);

#[bridge_fn(jni = false)]
fn CiphertextMessage_Type(msg: &CiphertextMessage) -> u8 {
    msg.message_type() as u8
}

bridge_get!(CiphertextMessage::serialize as Serialize -> &[u8], jni = false);

#[bridge_fn(jni = false)]
fn CiphertextMessage_FromPlaintextContent(m: &PlaintextContent) -> CiphertextMessage {
    CiphertextMessage::PlaintextContent(m.clone())
}

#[bridge_fn(ffi = false, node = false)]
fn SessionRecord_NewFresh() -> SessionRecord {
    SessionRecord::new_fresh()
}

#[bridge_fn(ffi = false, node = false)]
fn SessionRecord_FromSingleSessionState(session_state: &[u8]) -> Result<SessionRecord> {
    SessionRecord::from_single_session_state(session_state)
}

// For historical reasons Android assumes this function will return zero if there is no session state
#[bridge_fn(ffi = false, node = false)]
fn SessionRecord_GetSessionVersion(s: &SessionRecord) -> Result<u32> {
    match s.session_version() {
        Ok(v) => Ok(v),
        Err(SignalProtocolError::InvalidState(_, _)) => Ok(0),
        Err(e) => Err(e),
    }
}

#[bridge_fn_void]
fn SessionRecord_ArchiveCurrentState(session_record: &mut SessionRecord) -> Result<()> {
    session_record.archive_current_state()
}

#[bridge_fn]
fn SessionRecord_CurrentRatchetKeyMatches(s: &SessionRecord, key: &PublicKey) -> Result<bool> {
    s.current_ratchet_key_matches(key)
}

bridge_get!(SessionRecord::has_current_session_state as HasCurrentState -> bool, jni = false);

bridge_deserialize!(SessionRecord::deserialize);
bridge_get!(SessionRecord::serialize as Serialize -> Vec<u8>);
bridge_get!(SessionRecord::alice_base_key -> &[u8], ffi = false, node = false);
bridge_get!(
    SessionRecord::local_identity_key_bytes as GetLocalIdentityKeyPublic -> Vec<u8>,
    ffi = false,
    node = false
);
bridge_get!(
    SessionRecord::remote_identity_key_bytes as GetRemoteIdentityKeyPublic -> Option<Vec<u8>>,
    ffi = false,
    node = false
);
bridge_get!(SessionRecord::local_registration_id -> u32);
bridge_get!(SessionRecord::remote_registration_id -> u32);
bridge_get!(SessionRecord::has_sender_chain as HasSenderChain -> bool, ffi = false, node = false);

bridge_get!(SealedSenderDecryptionResult::sender_uuid -> String, ffi = false, jni = false);
bridge_get!(SealedSenderDecryptionResult::sender_e164 -> Option<String>, ffi = false, jni = false);
bridge_get!(SealedSenderDecryptionResult::device_id -> u32, ffi = false, jni = false);
bridge_get!(
    SealedSenderDecryptionResult::message as Message -> &[u8],
    ffi = false,
    jni = false
);

// The following SessionRecord APIs are just exposed to make it possible to retain some of the Java tests:

bridge_get!(
    SessionRecord::get_sender_chain_key_bytes as GetSenderChainKeyValue -> Vec<u8>,
    ffi = false,
    node = false
);
#[bridge_fn(ffi = false, node = false)]
fn SessionRecord_GetReceiverChainKeyValue(
    session_state: &SessionRecord,
    key: &PublicKey,
) -> Result<Option<Vec<u8>>> {
    Ok(session_state
        .get_receiver_chain_key_bytes(key)?
        .map(Vec::from))
}

#[bridge_fn(ffi = false, node = false)]
fn SessionRecord_InitializeAliceSession(
    identity_key_private: &PrivateKey,
    identity_key_public: &PublicKey,
    base_private: &PrivateKey,
    base_public: &PublicKey,
    their_identity_key: &PublicKey,
    their_signed_prekey: &PublicKey,
    their_ratchet_key: &PublicKey,
) -> Result<SessionRecord> {
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
        *their_ratchet_key,
    );

    initialize_alice_session_record(&parameters, &mut csprng)
}

#[bridge_fn(ffi = false, node = false)]
fn SessionRecord_InitializeBobSession(
    identity_key_private: &PrivateKey,
    identity_key_public: &PublicKey,
    signed_prekey_private: &PrivateKey,
    signed_prekey_public: &PublicKey,
    eph_private: &PrivateKey,
    eph_public: &PublicKey,
    their_identity_key: &PublicKey,
    their_base_key: &PublicKey,
) -> Result<SessionRecord> {
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
        None,
        their_identity_key,
        *their_base_key,
        None,
    );

    initialize_bob_session_record(&parameters)
}

// End SessionRecord testing functions

#[bridge_fn_void(ffi = "process_prekey_bundle")]
async fn SessionBuilder_ProcessPreKeyBundle(
    bundle: &PreKeyBundle,
    protocol_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_key_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<()> {
    let mut csprng = rand::rngs::OsRng;
    process_prekey_bundle(
        protocol_address,
        session_store,
        identity_key_store,
        bundle,
        &mut csprng,
        ctx,
    )
    .await
}

#[bridge_fn(ffi = "encrypt_message")]
async fn SessionCipher_EncryptMessage(
    ptext: &[u8],
    protocol_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_key_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<CiphertextMessage> {
    message_encrypt(
        ptext,
        protocol_address,
        session_store,
        identity_key_store,
        ctx,
    )
    .await
}

#[bridge_fn(ffi = "decrypt_message")]
async fn SessionCipher_DecryptSignalMessage(
    message: &SignalMessage,
    protocol_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_key_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<Vec<u8>> {
    let mut csprng = rand::rngs::OsRng;
    message_decrypt_signal(
        message,
        protocol_address,
        session_store,
        identity_key_store,
        &mut csprng,
        ctx,
    )
    .await
}

#[bridge_fn(ffi = "decrypt_pre_key_message")]
async fn SessionCipher_DecryptPreKeySignalMessage(
    message: &PreKeySignalMessage,
    protocol_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_key_store: &mut dyn IdentityKeyStore,
    prekey_store: &mut dyn PreKeyStore,
    signed_prekey_store: &mut dyn SignedPreKeyStore,
    kyber_prekey_store: &mut dyn KyberPreKeyStore,
    ctx: Context,
) -> Result<Vec<u8>> {
    let mut csprng = rand::rngs::OsRng;
    message_decrypt_prekey(
        message,
        protocol_address,
        session_store,
        identity_key_store,
        prekey_store,
        signed_prekey_store,
        kyber_prekey_store,
        &mut csprng,
        ctx,
    )
    .await
}

#[bridge_fn(node = "SealedSender_Encrypt")]
async fn SealedSessionCipher_Encrypt(
    destination: &ProtocolAddress,
    content: &UnidentifiedSenderMessageContent,
    identity_key_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<Vec<u8>> {
    let mut rng = rand::rngs::OsRng;
    sealed_sender_encrypt_from_usmc(destination, content, identity_key_store, ctx, &mut rng).await
}

#[bridge_fn(jni = "SealedSessionCipher_1MultiRecipientEncrypt", node = false)]
async fn SealedSender_MultiRecipientEncrypt(
    recipients: &[&ProtocolAddress],
    recipient_sessions: &[&SessionRecord],
    content: &UnidentifiedSenderMessageContent,
    identity_key_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<Vec<u8>> {
    let mut rng = rand::rngs::OsRng;
    sealed_sender_multi_recipient_encrypt(
        recipients,
        recipient_sessions,
        content,
        identity_key_store,
        ctx,
        &mut rng,
    )
    .await
}

// Node can't support the `&[&Foo]` type, so we clone the sessions instead.
#[bridge_fn(ffi = false, jni = false, node = "SealedSender_MultiRecipientEncrypt")]
async fn SealedSender_MultiRecipientEncryptNode(
    recipients: &[&ProtocolAddress],
    recipient_sessions: &[SessionRecord],
    content: &UnidentifiedSenderMessageContent,
    identity_key_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<Vec<u8>> {
    let mut rng = rand::rngs::OsRng;
    sealed_sender_multi_recipient_encrypt(
        recipients,
        &recipient_sessions.iter().collect::<Vec<&SessionRecord>>(),
        content,
        identity_key_store,
        ctx,
        &mut rng,
    )
    .await
}

#[bridge_fn(jni = "SealedSessionCipher_1MultiRecipientMessageForSingleRecipient")]
fn SealedSender_MultiRecipientMessageForSingleRecipient(
    encoded_multi_recipient_message: &[u8],
) -> Result<Vec<u8>> {
    let messages = sealed_sender_multi_recipient_fan_out(encoded_multi_recipient_message)?;
    let [single_message] = <[_; 1]>::try_from(messages).map_err(|_| {
        SignalProtocolError::InvalidArgument("encoded for more than one recipient".to_owned())
    })?;
    Ok(single_message)
}

#[bridge_fn(node = "SealedSender_DecryptToUsmc")]
async fn SealedSessionCipher_DecryptToUsmc(
    ctext: &[u8],
    identity_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<UnidentifiedSenderMessageContent> {
    sealed_sender_decrypt_to_usmc(ctext, identity_store, ctx).await
}

#[allow(clippy::too_many_arguments)]
#[bridge_fn(ffi = false, jni = false)]
async fn SealedSender_DecryptMessage(
    message: &[u8],
    trust_root: &PublicKey,
    timestamp: Timestamp,
    local_e164: Option<String>,
    local_uuid: String,
    local_device_id: u32,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    prekey_store: &mut dyn PreKeyStore,
    signed_prekey_store: &mut dyn SignedPreKeyStore,
    kyber_prekey_store: &mut dyn KyberPreKeyStore,
) -> Result<SealedSenderDecryptionResult> {
    sealed_sender_decrypt(
        message,
        trust_root,
        timestamp.as_millis(),
        local_e164,
        local_uuid,
        local_device_id.into(),
        identity_store,
        session_store,
        prekey_store,
        signed_prekey_store,
        kyber_prekey_store,
        None,
    )
    .await
}

#[bridge_fn(jni = "GroupSessionBuilder_1CreateSenderKeyDistributionMessage")]
async fn SenderKeyDistributionMessage_Create(
    sender: &ProtocolAddress,
    distribution_id: Uuid,
    store: &mut dyn SenderKeyStore,
    ctx: Context,
) -> Result<SenderKeyDistributionMessage> {
    let mut csprng = rand::rngs::OsRng;
    create_sender_key_distribution_message(sender, distribution_id, store, &mut csprng, ctx).await
}

#[bridge_fn_void(
    ffi = "process_sender_key_distribution_message",
    jni = "GroupSessionBuilder_1ProcessSenderKeyDistributionMessage"
)]
async fn SenderKeyDistributionMessage_Process(
    sender: &ProtocolAddress,
    sender_key_distribution_message: &SenderKeyDistributionMessage,
    store: &mut dyn SenderKeyStore,
    ctx: Context,
) -> Result<()> {
    process_sender_key_distribution_message(sender, sender_key_distribution_message, store, ctx)
        .await
}

#[bridge_fn(ffi = "group_encrypt_message")]
async fn GroupCipher_EncryptMessage(
    sender: &ProtocolAddress,
    distribution_id: Uuid,
    message: &[u8],
    store: &mut dyn SenderKeyStore,
    ctx: Context,
) -> Result<CiphertextMessage> {
    let mut rng = rand::rngs::OsRng;
    let ctext = group_encrypt(store, sender, distribution_id, message, &mut rng, ctx).await?;
    Ok(CiphertextMessage::SenderKeyMessage(ctext))
}

#[bridge_fn(ffi = "group_decrypt_message")]
async fn GroupCipher_DecryptMessage(
    sender: &ProtocolAddress,
    message: &[u8],
    store: &mut dyn SenderKeyStore,
    ctx: Context,
) -> Result<Vec<u8>> {
    group_decrypt(message, store, sender, ctx).await
}
