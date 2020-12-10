//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]

use aes_gcm_siv::Aes256GcmSiv;
use libsignal_protocol_rust::*;
use std::convert::TryFrom;

#[cfg(not(any(feature = "ffi", feature = "jni")))]
compile_error!("Either feature \"ffi\" or \"jni\" must be enabled for this crate.");

#[cfg(feature = "ffi")]
#[macro_use]
pub mod ffi;

#[cfg(feature = "jni")]
#[macro_use]
pub mod jni;

#[macro_use]
mod support;
use support::*;

bridge_destroy!(ProtocolAddress, ffi = address);
bridge_get_string!(name(ProtocolAddress), ffi = address_get_name =>
    |p| Ok(p.name())
);

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

bridge_destroy!(Fingerprint, jni = NumericFingerprintGenerator);
bridge_get_bytearray!(
    scannable_encoding(Fingerprint),
    jni = NumericFingerprintGenerator_1GetScannableEncoding =>
    |f| f.scannable.serialize()
);
bridge_get_string!(display_string(Fingerprint), jni = NumericFingerprintGenerator_1GetDisplayString =>
    Fingerprint::display_string
);

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

bridge_destroy!(SenderKeyDistributionMessage);
bridge_deserialize!(SenderKeyDistributionMessage::try_from);
bridge_get_bytearray!(get_chain_key(SenderKeyDistributionMessage) => SenderKeyDistributionMessage::chain_key);
bridge_get_bytearray!(get_signature_key(SenderKeyDistributionMessage), ffi = None =>
    |m| Ok(m.signing_key()?.serialize())
);
bridge_get_bytearray!(serialize(SenderKeyDistributionMessage), jni = SenderKeyDistributionMessage_1GetSerialized =>
    |m| Ok(m.serialized())
);

bridge_destroy!(PreKeyBundle);
bridge_get_bytearray!(get_signed_pre_key_signature(PreKeyBundle) => PreKeyBundle::signed_pre_key_signature);

bridge_destroy!(SignedPreKeyRecord);
bridge_deserialize!(SignedPreKeyRecord::deserialize);
bridge_get_bytearray!(get_signature(SignedPreKeyRecord) => SignedPreKeyRecord::signature);
bridge_get_bytearray!(serialize(SignedPreKeyRecord), jni = SignedPreKeyRecord_1GetSerialized =>
    SignedPreKeyRecord::serialize
);

bridge_destroy!(PreKeyRecord);
bridge_deserialize!(PreKeyRecord::deserialize);
bridge_get_bytearray!(serialize(PreKeyRecord), jni = PreKeyRecord_1GetSerialized =>
    PreKeyRecord::serialize
);

bridge_destroy!(SenderKeyName);
bridge_get_string!(get_group_id(SenderKeyName) => SenderKeyName::group_id);
bridge_get_string!(get_sender_name(SenderKeyName) => |skn| Ok(skn.sender()?.name().to_string()));

bridge_destroy!(SenderKeyRecord);
bridge_deserialize!(SenderKeyRecord::deserialize);
bridge_get_bytearray!(serialize(SenderKeyRecord), jni = SenderKeyRecord_1GetSerialized =>
    SenderKeyRecord::serialize
);

bridge_destroy!(CiphertextMessage, jni = None);

bridge_destroy!(ServerCertificate);
bridge_deserialize!(ServerCertificate::deserialize);
bridge_get_bytearray!(get_serialized(ServerCertificate) => ServerCertificate::serialized);
bridge_get_bytearray!(get_certificate(ServerCertificate) => ServerCertificate::certificate);
bridge_get_bytearray!(get_signature(ServerCertificate) => ServerCertificate::signature);

bridge_destroy!(SenderCertificate);
bridge_deserialize!(SenderCertificate::deserialize);
bridge_get_bytearray!(get_serialized(SenderCertificate) => SenderCertificate::serialized);
bridge_get_bytearray!(get_certificate(SenderCertificate) => SenderCertificate::certificate);
bridge_get_bytearray!(get_signature(SenderCertificate) => SenderCertificate::signature);
bridge_get_optional_string!(get_sender_uuid(SenderCertificate) => SenderCertificate::sender_uuid);
bridge_get_optional_string!(get_sender_e164(SenderCertificate) => SenderCertificate::sender_e164);

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

bridge_destroy!(UnidentifiedSenderMessage, ffi = None);
bridge_deserialize!(UnidentifiedSenderMessage::deserialize, ffi = None);
bridge_get_bytearray!(get_serialized(UnidentifiedSenderMessage), ffi = None =>
    UnidentifiedSenderMessage::serialized
);
bridge_get_bytearray!(get_encrypted_message(UnidentifiedSenderMessage), ffi = None =>
    UnidentifiedSenderMessage::encrypted_message
);
bridge_get_bytearray!(get_encrypted_static(UnidentifiedSenderMessage), ffi = None =>
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

bridge_destroy!(SessionState, ffi = None);
bridge_deserialize!(SessionState::deserialize, ffi = None);
bridge_get_bytearray!(serialized(SessionState) => SessionState::serialize);

bridge_destroy!(Aes256GcmSiv);
