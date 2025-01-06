//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ops::Range;
use std::time::SystemTime;

use aes_gcm_siv::aead::generic_array::typenum::Unsigned;
use aes_gcm_siv::{AeadInPlace, Aes256GcmSiv, KeyInit};
use arrayref::array_ref;
use indexmap::IndexMap;
use itertools::Itertools;
use prost::Message;
use proto::sealed_sender::unidentified_sender_message::message::Type as ProtoMessageType;
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;
use zerocopy::{FromBytes, FromZeroes};

use crate::{
    crypto, message_encrypt, proto, session_cipher, Aci, CiphertextMessageType, DeviceId,
    Direction, IdentityKey, IdentityKeyPair, IdentityKeyStore, KeyPair, KyberPreKeyStore,
    PreKeySignalMessage, PreKeyStore, PrivateKey, ProtocolAddress, PublicKey, Result, ServiceId,
    ServiceIdFixedWidthBinaryBytes, SessionRecord, SessionStore, SignalMessage,
    SignalProtocolError, SignedPreKeyStore, Timestamp,
};

#[derive(Debug, Clone)]
pub struct ServerCertificate {
    serialized: Vec<u8>,
    key_id: u32,
    key: PublicKey,
    certificate: Vec<u8>,
    signature: Vec<u8>,
}

/*
0xDEADC357 is a server certificate ID which is used to test the
revocation logic. As of this writing, no prod server certificates have
been revoked. If one ever does, add its key ID here.

If a production server certificate is ever generated which collides
with this test certificate ID, Bad Things will happen.
*/
const REVOKED_SERVER_CERTIFICATE_KEY_IDS: &[u32] = &[0xDEADC357];

// Valid registration IDs fit in 14 bits.
// TODO: move this into a RegistrationId strong type.
const VALID_REGISTRATION_ID_MASK: u16 = 0x3FFF;

// TODO: validate this as part of constructing DeviceId.
const MAX_VALID_DEVICE_ID: u32 = 127;

impl ServerCertificate {
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let pb = proto::sealed_sender::ServerCertificate::decode(data)
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;

        if pb.certificate.is_none() || pb.signature.is_none() {
            return Err(SignalProtocolError::InvalidProtobufEncoding);
        }

        let certificate = pb
            .certificate
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signature = pb
            .signature
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let certificate_data =
            proto::sealed_sender::server_certificate::Certificate::decode(certificate.as_ref())
                .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
        let key = PublicKey::try_from(
            &certificate_data
                .key
                .ok_or(SignalProtocolError::InvalidProtobufEncoding)?[..],
        )?;
        let key_id = certificate_data
            .id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

        Ok(Self {
            serialized: data.to_vec(),
            certificate,
            signature,
            key,
            key_id,
        })
    }

    pub fn new<R: Rng + CryptoRng>(
        key_id: u32,
        key: PublicKey,
        trust_root: &PrivateKey,
        rng: &mut R,
    ) -> Result<Self> {
        let certificate_pb = proto::sealed_sender::server_certificate::Certificate {
            id: Some(key_id),
            key: Some(key.serialize().to_vec()),
        };

        let certificate = certificate_pb.encode_to_vec();

        let signature = trust_root.calculate_signature(&certificate, rng)?.to_vec();

        let serialized = proto::sealed_sender::ServerCertificate {
            certificate: Some(certificate.clone()),
            signature: Some(signature.clone()),
        }
        .encode_to_vec();

        Ok(Self {
            serialized,
            certificate,
            signature,
            key,
            key_id,
        })
    }

    pub(crate) fn to_protobuf(&self) -> Result<proto::sealed_sender::ServerCertificate> {
        Ok(proto::sealed_sender::ServerCertificate {
            certificate: Some(self.certificate.clone()),
            signature: Some(self.signature.clone()),
        })
    }

    pub fn validate(&self, trust_root: &PublicKey) -> Result<bool> {
        if REVOKED_SERVER_CERTIFICATE_KEY_IDS.contains(&self.key_id()?) {
            log::error!(
                "received server certificate with revoked ID {:x}",
                self.key_id()?
            );
            return Ok(false);
        }
        Ok(trust_root.verify_signature(&self.certificate, &self.signature))
    }

    pub fn key_id(&self) -> Result<u32> {
        Ok(self.key_id)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        Ok(self.key)
    }

    pub fn certificate(&self) -> Result<&[u8]> {
        Ok(&self.certificate)
    }

    pub fn signature(&self) -> Result<&[u8]> {
        Ok(&self.signature)
    }

    pub fn serialized(&self) -> Result<&[u8]> {
        Ok(&self.serialized)
    }
}

#[derive(Debug, Clone)]
pub struct SenderCertificate {
    signer: ServerCertificate,
    key: PublicKey,
    sender_device_id: DeviceId,
    sender_uuid: String,
    sender_e164: Option<String>,
    expiration: Timestamp,
    serialized: Vec<u8>,
    certificate: Vec<u8>,
    signature: Vec<u8>,
}

impl SenderCertificate {
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let pb = proto::sealed_sender::SenderCertificate::decode(data)
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
        let certificate = pb
            .certificate
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signature = pb
            .signature
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let certificate_data =
            proto::sealed_sender::sender_certificate::Certificate::decode(certificate.as_ref())
                .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;

        let sender_device_id: DeviceId = certificate_data
            .sender_device
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            .into();
        let expiration = certificate_data
            .expires
            .map(Timestamp::from_epoch_millis)
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signer_pb = certificate_data
            .signer
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender_uuid = certificate_data
            .sender_uuid
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender_e164 = certificate_data.sender_e164;

        let key = PublicKey::try_from(
            &certificate_data
                .identity_key
                .ok_or(SignalProtocolError::InvalidProtobufEncoding)?[..],
        )?;

        let signer_bits = signer_pb.encode_to_vec();
        let signer = ServerCertificate::deserialize(&signer_bits)?;

        Ok(Self {
            signer,
            key,
            sender_device_id,
            sender_uuid,
            sender_e164,
            expiration,
            serialized: data.to_vec(),
            certificate,
            signature,
        })
    }

    pub fn new<R: Rng + CryptoRng>(
        sender_uuid: String,
        sender_e164: Option<String>,
        key: PublicKey,
        sender_device_id: DeviceId,
        expiration: Timestamp,
        signer: ServerCertificate,
        signer_key: &PrivateKey,
        rng: &mut R,
    ) -> Result<Self> {
        let certificate_pb = proto::sealed_sender::sender_certificate::Certificate {
            sender_uuid: Some(sender_uuid.clone()),
            sender_e164: sender_e164.clone(),
            sender_device: Some(sender_device_id.into()),
            expires: Some(expiration.epoch_millis()),
            identity_key: Some(key.serialize().to_vec()),
            signer: Some(signer.to_protobuf()?),
        };

        let certificate = certificate_pb.encode_to_vec();

        let signature = signer_key.calculate_signature(&certificate, rng)?.to_vec();

        let serialized = proto::sealed_sender::SenderCertificate {
            certificate: Some(certificate.clone()),
            signature: Some(signature.clone()),
        }
        .encode_to_vec();

        Ok(Self {
            signer,
            key,
            sender_device_id,
            sender_uuid,
            sender_e164,
            expiration,
            serialized,
            certificate,
            signature,
        })
    }

    pub fn validate(&self, trust_root: &PublicKey, validation_time: Timestamp) -> Result<bool> {
        if !self.signer.validate(trust_root)? {
            log::error!(
                "sender certificate contained server certificate that wasn't signed by trust root"
            );
            return Ok(false);
        }

        if !self
            .signer
            .public_key()?
            .verify_signature(&self.certificate, &self.signature)
        {
            log::error!("sender certificate not signed by server");
            return Ok(false);
        }

        if validation_time > self.expiration {
            log::error!(
                "sender certificate is expired (expiration: {}, validation_time: {})",
                self.expiration.epoch_millis(),
                validation_time.epoch_millis()
            );
            return Ok(false);
        }

        Ok(true)
    }

    pub fn signer(&self) -> Result<&ServerCertificate> {
        Ok(&self.signer)
    }

    pub fn key(&self) -> Result<PublicKey> {
        Ok(self.key)
    }

    pub fn sender_device_id(&self) -> Result<DeviceId> {
        Ok(self.sender_device_id)
    }

    pub fn sender_uuid(&self) -> Result<&str> {
        Ok(&self.sender_uuid)
    }

    pub fn sender_e164(&self) -> Result<Option<&str>> {
        Ok(self.sender_e164.as_deref())
    }

    pub fn expiration(&self) -> Result<Timestamp> {
        Ok(self.expiration)
    }

    pub fn serialized(&self) -> Result<&[u8]> {
        Ok(&self.serialized)
    }

    pub fn certificate(&self) -> Result<&[u8]> {
        Ok(&self.certificate)
    }

    pub fn signature(&self) -> Result<&[u8]> {
        Ok(&self.signature)
    }
}

impl From<ProtoMessageType> for CiphertextMessageType {
    fn from(message_type: ProtoMessageType) -> Self {
        let result = match message_type {
            ProtoMessageType::Message => Self::Whisper,
            ProtoMessageType::PrekeyMessage => Self::PreKey,
            ProtoMessageType::SenderkeyMessage => Self::SenderKey,
            ProtoMessageType::PlaintextContent => Self::Plaintext,
        };
        // Keep raw values in sync from now on, for efficient codegen.
        assert!(result == Self::PreKey || message_type as i32 == result as i32);
        result
    }
}

impl From<CiphertextMessageType> for ProtoMessageType {
    fn from(message_type: CiphertextMessageType) -> Self {
        let result = match message_type {
            CiphertextMessageType::PreKey => Self::PrekeyMessage,
            CiphertextMessageType::Whisper => Self::Message,
            CiphertextMessageType::SenderKey => Self::SenderkeyMessage,
            CiphertextMessageType::Plaintext => Self::PlaintextContent,
        };
        // Keep raw values in sync from now on, for efficient codegen.
        assert!(result == Self::PrekeyMessage || message_type as i32 == result as i32);
        result
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContentHint {
    Default,
    Resendable,
    Implicit,
    Unknown(u32),
}

impl ContentHint {
    fn to_proto(self) -> Option<i32> {
        if self == ContentHint::Default {
            None
        } else {
            Some(u32::from(self) as i32)
        }
    }

    pub const fn to_u32(self) -> u32 {
        use proto::sealed_sender::unidentified_sender_message::message::ContentHint as ProtoContentHint;
        match self {
            ContentHint::Default => 0,
            ContentHint::Resendable => ProtoContentHint::Resendable as u32,
            ContentHint::Implicit => ProtoContentHint::Implicit as u32,
            ContentHint::Unknown(value) => value,
        }
    }
}

impl From<u32> for ContentHint {
    fn from(raw_value: u32) -> Self {
        use proto::sealed_sender::unidentified_sender_message::message::ContentHint as ProtoContentHint;
        assert!(!ProtoContentHint::is_valid(0));
        match ProtoContentHint::try_from(raw_value as i32) {
            Err(_) if raw_value == 0 => ContentHint::Default,
            Err(_) => ContentHint::Unknown(raw_value),
            Ok(ProtoContentHint::Resendable) => ContentHint::Resendable,
            Ok(ProtoContentHint::Implicit) => ContentHint::Implicit,
        }
    }
}

impl From<ContentHint> for u32 {
    fn from(hint: ContentHint) -> Self {
        hint.to_u32()
    }
}

pub struct UnidentifiedSenderMessageContent {
    serialized: Vec<u8>,
    contents: Vec<u8>,
    sender: SenderCertificate,
    msg_type: CiphertextMessageType,
    content_hint: ContentHint,
    group_id: Option<Vec<u8>>,
}

impl UnidentifiedSenderMessageContent {
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let pb = proto::sealed_sender::unidentified_sender_message::Message::decode(data)
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;

        let msg_type = pb
            .r#type
            .and_then(|t| ProtoMessageType::try_from(t).ok())
            .map(CiphertextMessageType::from)
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender = pb
            .sender_certificate
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let contents = pb
            .content
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let content_hint = pb
            .content_hint
            .map(|raw| ContentHint::from(raw as u32))
            .unwrap_or(ContentHint::Default);
        let group_id = pb.group_id;

        let sender = SenderCertificate::deserialize(&sender)?;

        let serialized = data.to_vec();

        log::info!(
            "deserialized UnidentifiedSenderMessageContent from {}.{} with type {:?}",
            sender.sender_uuid()?,
            sender.sender_device_id()?,
            msg_type,
        );

        Ok(Self {
            serialized,
            contents,
            sender,
            msg_type,
            content_hint,
            group_id,
        })
    }

    pub fn new(
        msg_type: CiphertextMessageType,
        sender: SenderCertificate,
        contents: Vec<u8>,
        content_hint: ContentHint,
        group_id: Option<Vec<u8>>,
    ) -> Result<Self> {
        let proto_msg_type = ProtoMessageType::from(msg_type);
        let msg = proto::sealed_sender::unidentified_sender_message::Message {
            content: Some(contents.clone()),
            r#type: Some(proto_msg_type.into()),
            sender_certificate: Some(sender.serialized()?.to_vec()),
            content_hint: content_hint.to_proto(),
            group_id: group_id.as_ref().and_then(|buf| {
                if buf.is_empty() {
                    None
                } else {
                    Some(buf.clone())
                }
            }),
        };

        let serialized = msg.encode_to_vec();

        Ok(Self {
            serialized,
            msg_type,
            sender,
            contents,
            content_hint,
            group_id,
        })
    }

    pub fn msg_type(&self) -> Result<CiphertextMessageType> {
        Ok(self.msg_type)
    }

    pub fn sender(&self) -> Result<&SenderCertificate> {
        Ok(&self.sender)
    }

    pub fn contents(&self) -> Result<&[u8]> {
        Ok(&self.contents)
    }

    pub fn content_hint(&self) -> Result<ContentHint> {
        Ok(self.content_hint)
    }

    pub fn group_id(&self) -> Result<Option<&[u8]>> {
        Ok(self.group_id.as_deref())
    }

    pub fn serialized(&self) -> Result<&[u8]> {
        Ok(&self.serialized)
    }
}

enum UnidentifiedSenderMessage<'a> {
    V1 {
        ephemeral_public: PublicKey,
        encrypted_static: Vec<u8>,
        encrypted_message: Vec<u8>,
    },
    V2 {
        ephemeral_public: PublicKey,
        encrypted_message_key: &'a [u8; sealed_sender_v2::MESSAGE_KEY_LEN],
        authentication_tag: &'a [u8; sealed_sender_v2::AUTH_TAG_LEN],
        encrypted_message: &'a [u8],
    },
}

const SEALED_SENDER_V1_MAJOR_VERSION: u8 = 1;
const SEALED_SENDER_V1_FULL_VERSION: u8 = 0x11;
const SEALED_SENDER_V2_MAJOR_VERSION: u8 = 2;
const SEALED_SENDER_V2_UUID_FULL_VERSION: u8 = 0x22;
const SEALED_SENDER_V2_SERVICE_ID_FULL_VERSION: u8 = 0x23;

impl<'a> UnidentifiedSenderMessage<'a> {
    fn deserialize(data: &'a [u8]) -> Result<Self> {
        let (version_byte, remaining) = data.split_first().ok_or_else(|| {
            SignalProtocolError::InvalidSealedSenderMessage("Message was empty".to_owned())
        })?;
        let version = version_byte >> 4;
        log::debug!(
            "deserializing UnidentifiedSenderMessage with version {}",
            version
        );

        match version {
            0 | SEALED_SENDER_V1_MAJOR_VERSION => {
                // XXX should we really be accepted version == 0 here?
                let pb = proto::sealed_sender::UnidentifiedSenderMessage::decode(remaining)
                    .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;

                let ephemeral_public = pb
                    .ephemeral_public
                    .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
                let encrypted_static = pb
                    .encrypted_static
                    .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
                let encrypted_message = pb
                    .encrypted_message
                    .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

                let ephemeral_public = PublicKey::try_from(&ephemeral_public[..])?;

                Ok(Self::V1 {
                    ephemeral_public,
                    encrypted_static,
                    encrypted_message,
                })
            }
            SEALED_SENDER_V2_MAJOR_VERSION => {
                /// Uses a flat representation: C || AT || E.pub || ciphertext
                #[repr(packed)]
                #[derive(FromBytes, FromZeroes)]
                struct PrefixRepr {
                    encrypted_message_key: [u8; sealed_sender_v2::MESSAGE_KEY_LEN],
                    encrypted_authentication_tag: [u8; sealed_sender_v2::AUTH_TAG_LEN],
                    ephemeral_public: [u8; sealed_sender_v2::PUBLIC_KEY_LEN],
                }
                let (prefix, encrypted_message) =
                    zerocopy::Ref::<_, PrefixRepr>::new_from_prefix(remaining)
                        .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

                let PrefixRepr {
                    encrypted_message_key,
                    encrypted_authentication_tag,
                    ephemeral_public,
                } = prefix.into_ref();

                Ok(Self::V2 {
                    ephemeral_public: PublicKey::from_djb_public_key_bytes(
                        ephemeral_public.as_slice(),
                    )?,
                    encrypted_message_key,
                    authentication_tag: encrypted_authentication_tag,
                    encrypted_message,
                })
            }
            _ => Err(SignalProtocolError::UnknownSealedSenderVersion(version)),
        }
    }
}

mod sealed_sender_v1 {
    #[cfg(test)]
    use std::fmt;

    use super::*;

    /// A symmetric cipher key and a MAC key, along with a "chain key" consumed in
    /// [`StaticKeys::calculate`].
    pub(super) struct EphemeralKeys {
        pub(super) chain_key: [u8; 32],
        pub(super) cipher_key: [u8; 32],
        pub(super) mac_key: [u8; 32],
    }

    const SALT_PREFIX: &[u8] = b"UnidentifiedDelivery";
    const EPHEMERAL_KEYS_KDF_LEN: usize = 96;

    impl EphemeralKeys {
        /// Derive a set of symmetric keys from the key agreement between the sender and
        /// recipient's identities.
        pub(super) fn calculate(
            our_keys: &KeyPair,
            their_public: &PublicKey,
            direction: Direction,
        ) -> Result<Self> {
            let our_pub_key = our_keys.public_key.serialize();
            let their_pub_key = their_public.serialize();
            let ephemeral_salt = match direction {
                Direction::Sending => [SALT_PREFIX, &their_pub_key, &our_pub_key],
                Direction::Receiving => [SALT_PREFIX, &our_pub_key, &their_pub_key],
            }
            .concat();

            let shared_secret = our_keys.private_key.calculate_agreement(their_public)?;
            let mut derived_values = [0; EPHEMERAL_KEYS_KDF_LEN];
            hkdf::Hkdf::<sha2::Sha256>::new(Some(&ephemeral_salt), &shared_secret)
                .expand(&[], &mut derived_values)
                .expect("valid output length");

            Ok(Self {
                chain_key: *array_ref![&derived_values, 0, 32],
                cipher_key: *array_ref![&derived_values, 32, 32],
                mac_key: *array_ref![&derived_values, 64, 32],
            })
        }
    }

    #[cfg(test)]
    impl PartialEq for EphemeralKeys {
        fn eq(&self, other: &Self) -> bool {
            self.chain_key == other.chain_key
                && self.cipher_key == other.cipher_key
                && self.mac_key == other.mac_key
        }
    }

    #[cfg(test)]
    impl Eq for EphemeralKeys {}

    #[cfg(test)]
    impl fmt::Debug for EphemeralKeys {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "EphemeralKeys {{ chain_key: {:?}, cipher_key: {:?}, mac_key: {:?} }}",
                self.chain_key, self.cipher_key, self.mac_key
            )
        }
    }

    /// A symmetric cipher key and a MAC key.
    pub(super) struct StaticKeys {
        pub(super) cipher_key: [u8; 32],
        pub(super) mac_key: [u8; 32],
    }

    impl StaticKeys {
        /// Derive a set of symmetric keys from the agreement between the sender and
        /// recipient's identities, as well as [`EphemeralKeys::chain_key`].
        pub(super) fn calculate(
            our_keys: &IdentityKeyPair,
            their_key: &PublicKey,
            chain_key: &[u8; 32],
            ctext: &[u8],
        ) -> Result<Self> {
            let salt = [chain_key, ctext].concat();

            let shared_secret = our_keys.private_key().calculate_agreement(their_key)?;
            // 96 bytes are derived, but the first 32 are discarded/unused. This is intended to
            // mirror the way the EphemeralKeys are derived, even though StaticKeys does not end up
            // requiring a third "chain key".
            let mut derived_values = [0; 96];
            hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &shared_secret)
                .expand(&[], &mut derived_values)
                .expect("valid output length");

            Ok(Self {
                cipher_key: *array_ref![&derived_values, 32, 32],
                mac_key: *array_ref![&derived_values, 64, 32],
            })
        }
    }

    #[test]
    fn test_agreement_and_authentication() -> Result<()> {
        // The sender and recipient each have a long-term identity key pair.
        let sender_identity = IdentityKeyPair::generate(&mut rand::thread_rng());
        let recipient_identity = IdentityKeyPair::generate(&mut rand::thread_rng());

        // Generate an ephemeral key pair.
        let sender_ephemeral = KeyPair::generate(&mut rand::thread_rng());
        let ephemeral_public = sender_ephemeral.public_key;
        // Generate ephemeral cipher, chain, and MAC keys.
        let sender_eph_keys = EphemeralKeys::calculate(
            &sender_ephemeral,
            recipient_identity.public_key(),
            Direction::Sending,
        )?;

        // Encrypt the sender's public key with AES-256 CTR and a MAC.
        let sender_static_key_ctext = crypto::aes256_ctr_hmacsha256_encrypt(
            &sender_identity.public_key().serialize(),
            &sender_eph_keys.cipher_key,
            &sender_eph_keys.mac_key,
        )
        .expect("just generated these keys, they should be correct");

        // Generate another cipher and MAC key.
        let sender_static_keys = StaticKeys::calculate(
            &sender_identity,
            recipient_identity.public_key(),
            &sender_eph_keys.chain_key,
            &sender_static_key_ctext,
        )?;

        let sender_message_contents = b"this is a binary message";
        let sender_message_data = crypto::aes256_ctr_hmacsha256_encrypt(
            sender_message_contents,
            &sender_static_keys.cipher_key,
            &sender_static_keys.mac_key,
        )
        .expect("just generated these keys, they should be correct");

        // The message recipient calculates the ephemeral key and the sender's public key.
        let recipient_eph_keys = EphemeralKeys::calculate(
            &recipient_identity.into(),
            &ephemeral_public,
            Direction::Receiving,
        )?;
        assert_eq!(sender_eph_keys, recipient_eph_keys);

        let recipient_message_key_bytes = crypto::aes256_ctr_hmacsha256_decrypt(
            &sender_static_key_ctext,
            &recipient_eph_keys.cipher_key,
            &recipient_eph_keys.mac_key,
        )
        .expect("should decrypt successfully");
        let sender_public_key: PublicKey = PublicKey::try_from(&recipient_message_key_bytes[..])?;
        assert_eq!(sender_identity.public_key(), &sender_public_key);

        let recipient_static_keys = StaticKeys::calculate(
            &recipient_identity,
            &sender_public_key,
            &recipient_eph_keys.chain_key,
            &sender_static_key_ctext,
        )?;

        let recipient_message_contents = crypto::aes256_ctr_hmacsha256_decrypt(
            &sender_message_data,
            &recipient_static_keys.cipher_key,
            &recipient_static_keys.mac_key,
        )
        .expect("should decrypt successfully");
        assert_eq!(recipient_message_contents, sender_message_contents);

        Ok(())
    }
}

/// Encrypt the plaintext message `ptext`, generate an [`UnidentifiedSenderMessageContent`], then
/// pass the result to [`sealed_sender_encrypt_from_usmc`].
///
/// This is a simple way to encrypt a message in a 1:1 using [Sealed Sender v1].
///
/// [Sealed Sender v1]: sealed_sender_encrypt_from_usmc
pub async fn sealed_sender_encrypt<R: Rng + CryptoRng>(
    destination: &ProtocolAddress,
    sender_cert: &SenderCertificate,
    ptext: &[u8],
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    now: SystemTime,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let message = message_encrypt(ptext, destination, session_store, identity_store, now).await?;
    let usmc = UnidentifiedSenderMessageContent::new(
        message.message_type(),
        sender_cert.clone(),
        message.serialize().to_vec(),
        ContentHint::Default,
        None,
    )?;
    sealed_sender_encrypt_from_usmc(destination, &usmc, identity_store, rng).await
}

/// This method implements the single-key single-recipient [KEM] described in [this Signal blog
/// post], a.k.a. Sealed Sender v1.
///
/// [KEM]: https://en.wikipedia.org/wiki/Key_encapsulation
/// [this Signal blog post]: https://signal.org/blog/sealed-sender/
///
/// [`sealed_sender_decrypt`] is used in the client to decrypt the Sealed Sender message produced by
/// this method.
///
/// # Contrast with Sealed Sender v2
/// The *single-recipient* KEM scheme implemented by this method partially derives the encryption
/// key from the recipient's identity key, which would then require re-encrypting the same message
/// multiple times to send to multiple recipients. In contrast,
/// [Sealed Sender v2](sealed_sender_multi_recipient_encrypt) uses a *multi-recipient* KEM scheme
/// which avoids this repeated work, but makes a few additional design tradeoffs.
///
/// # High-level algorithmic overview
/// The KEM scheme implemented by this method is described in [this Signal blog post]. The
/// high-level steps of this process are listed below:
/// 1. Generate a random key pair.
/// 2. Derive a symmetric chain key, cipher key, and MAC key from the recipient's public key and the
///    sender's public/private key pair.
/// 3. Symmetrically encrypt the sender's public key using the cipher key and MAC key from (2) with
///    AES-256 in CTR mode.
/// 4. Derive a second symmetric cipher key and MAC key from the sender's private key, the
///    recipient's public key, and the chain key from (2).
/// 5. Symmetrically encrypt the underlying [`UnidentifiedSenderMessageContent`] using the cipher key
///    and MAC key from (4) with AES-256 in CTR mode.
/// 6. Send the ephemeral public key from (1) and the encrypted public key from (3) to the
///    recipient, along with the encrypted message (5).
///
/// ## Pseudocode
///```text
/// e_pub, e_priv                  = X25519.generateEphemeral()
/// e_chain, e_cipherKey, e_macKey = HKDF(salt="UnidentifiedDelivery" || recipientIdentityPublic || e_pub, ikm=ECDH(recipientIdentityPublic, e_priv), info="")
/// e_ciphertext                   = AES_CTR(key=e_cipherKey, input=senderIdentityPublic)
/// e_mac                          = Hmac256(key=e_macKey, input=e_ciphertext)
///
/// s_cipherKey, s_macKey = HKDF(salt=e_chain || e_ciphertext || e_mac, ikm=ECDH(recipientIdentityPublic, senderIdentityPrivate), info="")
/// s_ciphertext          = AES_CTR(key=s_cipherKey, input=sender_certificate || message_ciphertext)
/// s_mac                 = Hmac256(key=s_macKey, input=s_ciphertext)
///
/// message_to_send = s_ciphertext || s_mac
///```
///
/// # Wire Format
/// The output of this method is encoded as an `UnidentifiedSenderMessage.Message` from
/// `sealed_sender.proto`, prepended with an additional byte to indicate the version of Sealed
/// Sender in use (see [further documentation on the version
/// byte](sealed_sender_multi_recipient_encrypt#the-version-byte)).
pub async fn sealed_sender_encrypt_from_usmc<R: Rng + CryptoRng>(
    destination: &ProtocolAddress,
    usmc: &UnidentifiedSenderMessageContent,
    identity_store: &dyn IdentityKeyStore,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let our_identity = identity_store.get_identity_key_pair().await?;
    let their_identity = identity_store
        .get_identity(destination)
        .await?
        .ok_or_else(|| SignalProtocolError::SessionNotFound(destination.clone()))?;

    let ephemeral = KeyPair::generate(rng);

    let eph_keys = sealed_sender_v1::EphemeralKeys::calculate(
        &ephemeral,
        their_identity.public_key(),
        Direction::Sending,
    )?;

    let static_key_ctext = crypto::aes256_ctr_hmacsha256_encrypt(
        &our_identity.public_key().serialize(),
        &eph_keys.cipher_key,
        &eph_keys.mac_key,
    )
    .expect("just generated these keys, they should be correct");

    let static_keys = sealed_sender_v1::StaticKeys::calculate(
        &our_identity,
        their_identity.public_key(),
        &eph_keys.chain_key,
        &static_key_ctext,
    )?;

    let message_data = crypto::aes256_ctr_hmacsha256_encrypt(
        usmc.serialized()?,
        &static_keys.cipher_key,
        &static_keys.mac_key,
    )
    .expect("just generated these keys, they should be correct");

    let mut serialized = vec![SEALED_SENDER_V1_FULL_VERSION];
    let pb = proto::sealed_sender::UnidentifiedSenderMessage {
        ephemeral_public: Some(ephemeral.public_key.serialize().to_vec()),
        encrypted_static: Some(static_key_ctext),
        encrypted_message: Some(message_data),
    };
    pb.encode(&mut serialized)
        .expect("can always append to Vec");

    Ok(serialized)
}

mod sealed_sender_v2 {
    use super::*;

    // Static byte strings used as part of a MAC in HKDF.
    const LABEL_R: &[u8] = b"Sealed Sender v2: r (2023-08)";
    const LABEL_K: &[u8] = b"Sealed Sender v2: K";
    const LABEL_DH: &[u8] = b"Sealed Sender v2: DH";
    const LABEL_DH_S: &[u8] = b"Sealed Sender v2: DH-sender";

    pub const MESSAGE_KEY_LEN: usize = 32;
    pub const CIPHER_KEY_LEN: usize =
        <Aes256GcmSiv as aes_gcm_siv::aead::KeySizeUser>::KeySize::USIZE;
    pub const AUTH_TAG_LEN: usize = 16;
    /// SSv2 hardcodes that its keys are Curve25519 public keys.
    pub const PUBLIC_KEY_LEN: usize = 32;

    /// An asymmetric and a symmetric cipher key.
    pub(super) struct DerivedKeys {
        kdf: hkdf::Hkdf<sha2::Sha256>,
    }

    impl DerivedKeys {
        /// Initialize from a slice of random bytes `m`.
        pub(super) fn new(m: &[u8]) -> DerivedKeys {
            Self {
                kdf: hkdf::Hkdf::<sha2::Sha256>::new(None, m),
            }
        }

        /// Derive the ephemeral asymmetric keys.
        pub(super) fn derive_e(&self) -> KeyPair {
            let mut r = [0; 32];
            self.kdf
                .expand(LABEL_R, &mut r)
                .expect("valid output length");
            let e = PrivateKey::try_from(&r[..]).expect("valid PrivateKey");
            KeyPair::try_from(e).expect("can derive public key")
        }

        /// Derive the symmetric cipher key.
        pub(super) fn derive_k(&self) -> [u8; CIPHER_KEY_LEN] {
            let mut k = [0; CIPHER_KEY_LEN];
            self.kdf
                .expand(LABEL_K, &mut k)
                .expect("valid output length");
            k
        }
    }

    /// Encrypt or decrypt a slice of random bytes `input` using a shared secret derived from
    /// `our_keys` and `their_key`.
    ///
    /// The output of this method when called with [`Direction::Sending`] can be inverted to produce
    /// the original `input` bytes if called with [`Direction::Receiving`] with `our_keys` and
    /// `their_key` swapped.
    pub(super) fn apply_agreement_xor(
        our_keys: &KeyPair,
        their_key: &PublicKey,
        direction: Direction,
        input: &[u8; MESSAGE_KEY_LEN],
    ) -> Result<[u8; MESSAGE_KEY_LEN]> {
        let agreement = our_keys.calculate_agreement(their_key)?;
        let agreement_key_input = match direction {
            Direction::Sending => [
                agreement,
                our_keys.public_key.serialize(),
                their_key.serialize(),
            ],
            Direction::Receiving => [
                agreement,
                their_key.serialize(),
                our_keys.public_key.serialize(),
            ],
        }
        .concat();

        let mut result = [0; MESSAGE_KEY_LEN];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &agreement_key_input)
            .expand(LABEL_DH, &mut result)
            .expect("valid output length");
        result
            .iter_mut()
            .zip(input)
            .for_each(|(result_byte, input_byte)| *result_byte ^= input_byte);
        Ok(result)
    }

    /// Compute an [authentication tag] for the bytes `encrypted_message_key` using a shared secret
    /// derived from `our_keys` and `their_key`.
    ///
    /// [authentication tag]: https://en.wikipedia.org/wiki/Message_authentication_code
    ///
    /// The output of this method with [`Direction::Sending`] should be the same bytes produced by
    /// calling this method with [`Direction::Receiving`] with `our_keys` and `their_key`
    /// swapped, if `ephemeral_pub_key` and `encrypted_message_key` are the same.
    pub(super) fn compute_authentication_tag(
        our_keys: &IdentityKeyPair,
        their_key: &IdentityKey,
        direction: Direction,
        ephemeral_pub_key: &PublicKey,
        encrypted_message_key: &[u8; MESSAGE_KEY_LEN],
    ) -> Result<[u8; AUTH_TAG_LEN]> {
        let agreement = our_keys
            .private_key()
            .calculate_agreement(their_key.public_key())?;
        let mut agreement_key_input = agreement.into_vec();
        agreement_key_input.extend_from_slice(&ephemeral_pub_key.serialize());
        agreement_key_input.extend_from_slice(encrypted_message_key);
        match direction {
            Direction::Sending => {
                agreement_key_input.extend_from_slice(&our_keys.public_key().serialize());
                agreement_key_input.extend_from_slice(&their_key.serialize());
            }
            Direction::Receiving => {
                agreement_key_input.extend_from_slice(&their_key.serialize());
                agreement_key_input.extend_from_slice(&our_keys.public_key().serialize());
            }
        }

        let mut result = [0; AUTH_TAG_LEN];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &agreement_key_input)
            .expand(LABEL_DH_S, &mut result)
            .expect("valid output length");
        Ok(result)
    }

    #[test]
    fn test_agreement_and_authentication() -> Result<()> {
        // The sender and recipient each have a long-term identity key pair.
        let sender_identity = IdentityKeyPair::generate(&mut rand::thread_rng());
        let recipient_identity = IdentityKeyPair::generate(&mut rand::thread_rng());

        // Generate random bytes used for our multi-recipient encoding scheme.
        let m: [u8; MESSAGE_KEY_LEN] = rand::thread_rng().gen();
        // Derive an ephemeral key pair from those random bytes.
        let ephemeral_keys = DerivedKeys::new(&m);
        let e = ephemeral_keys.derive_e();

        // Encrypt the ephemeral key pair.
        let sender_c_0: [u8; MESSAGE_KEY_LEN] =
            apply_agreement_xor(&e, recipient_identity.public_key(), Direction::Sending, &m)?;
        // Compute an authentication tag for the encrypted key pair.
        let sender_at_0 = compute_authentication_tag(
            &sender_identity,
            recipient_identity.identity_key(),
            Direction::Sending,
            &e.public_key,
            &sender_c_0,
        )?;

        // The message recipient calculates the original random bytes and authenticates the result.
        let recv_m = apply_agreement_xor(
            &recipient_identity.into(),
            &e.public_key,
            Direction::Receiving,
            &sender_c_0,
        )?;
        assert_eq!(&recv_m, &m);

        let recv_at_0 = compute_authentication_tag(
            &recipient_identity,
            sender_identity.identity_key(),
            Direction::Receiving,
            &e.public_key,
            &sender_c_0,
        )?;
        assert_eq!(&recv_at_0, &sender_at_0);

        Ok(())
    }
}

/// This method implements a single-key multi-recipient [KEM] as defined in Manuel Barbosa's
/// ["Randomness Reuse: Extensions and Improvements"], a.k.a. Sealed Sender v2.
///
/// [KEM]: https://en.wikipedia.org/wiki/Key_encapsulation
/// ["Randomness Reuse: Extensions and Improvements"]: https://haslab.uminho.pt/mbb/files/reuse.pdf
///
/// # Contrast with Sealed Sender v1
/// The KEM scheme implemented by this method uses the "Generic Construction" in `4.1` of [Barbosa's
/// paper]["Randomness Reuse: Extensions and Improvements"], instantiated with [ElGamal encryption].
/// This technique enables reusing a single sequence of random bytes across multiple messages with
/// the same content, which reduces computation time for clients sending the same message to
/// multiple recipients (without compromising the message security).
///
/// There are a few additional design tradeoffs this method makes vs [Sealed Sender v1] which may
/// make it comparatively unwieldy for certain scenarios:
/// 1. it requires a [`SessionRecord`] to exist already for the recipient, i.e. that a Double
///    Ratchet message chain has previously been established in the [`SessionStore`] via
///    [`process_prekey_bundle`][crate::process_prekey_bundle] after an initial
///    [`PreKeySignalMessage`] is received.
/// 2. it ferries a lot of additional information in its encoding which makes the resulting message
///    bulkier than the message produced by [Sealed Sender v1]. For sending, this will generally
///    still be more compact than sending the same message N times, but on the receiver side the
///    message is slightly larger.
/// 3. unlike other message types sent over the wire, the encoded message returned by this method
///    does not use protobuf, in order to avoid inefficiencies produced by protobuf's packing (see
///    **[Wire Format]**).
///
/// [ElGamal encryption]: https://en.wikipedia.org/wiki/ElGamal_encryption
/// [Sealed Sender v1]: sealed_sender_encrypt_from_usmc
/// [Wire Format]: #wire-format
///
/// # High-level algorithmic overview
/// The high-level steps of this process are summarized below:
/// 1. Generate a series of random bytes.
/// 2. Derive an ephemeral key pair from (1).
/// 3. *Once per recipient:* Encrypt (1) using a shared secret derived from the private ephemeral
///    key (2) and the recipient's public identity key.
/// 4. *Once per recipient:* Add an authentication tag for (3) using a secret derived from the
///    sender's private identity key and the recipient's public identity key.
/// 5. Generate a symmetric key from (1) and use it to symmetrically encrypt the underlying
///    [`UnidentifiedSenderMessageContent`] via [AEAD encryption]. *This step is only performed once
///    per message, regardless of the number of recipients.*
/// 6. Send the public ephemeral key (2) to the server, along with the sequence of encrypted random
///    bytes (3) and authentication tags (4), and the single encrypted message (5).
///
/// [AEAD encryption]:
///    https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)
///
/// ## Pseudocode
///```text
/// ENCRYPT(message, R_i):
///     M = Random(32)
///     r = KDF(label_r, M, len=32)
///     K = KDF(label_K, M, len=32)
///     E = DeriveKeyPair(r)
///     for i in num_recipients:
///         C_i = KDF(label_DH, DH(E, R_i) || E.public || R_i.public, len=32) XOR M
///         AT_i = KDF(label_DH_s, DH(S, R_i) || E.public || C_i || S.public || R_i.public, len=16)
///     ciphertext = AEAD_Encrypt(K, message)
///     return E.public, C_i, AT_i, ciphertext
///
/// DECRYPT(E.public, C, AT, ciphertext):
///     M = KDF(label_DH, DH(E, R) || E.public || R.public, len=32) xor C
///     r = KDF(label_r, M, len=32)
///     K = KDF(label_K, M, len=32)
///     E' = DeriveKeyPair(r)
///     if E.public != E'.public:
///         return DecryptionError
///     message = AEAD_Decrypt(K, ciphertext) // includes S.public
///     AT' = KDF(label_DH_s, DH(S, R) || E.public || C || S.public || R.public, len=16)
///     if AT != AT':
///         return DecryptionError
///     return message
///```
///
/// # Routing messages to recipients
///
/// The server will split up the set of messages and securely route each individual [received
/// message][receiving] to its intended recipient. [`SealedSenderV2SentMessage`] can perform this
/// fan-out operation.
///
/// # Wire Format
/// Multi-recipient sealed-sender does not use protobufs for its payload format. Instead, it uses a
/// flat format marked with a [version byte](#the-version-byte). The format is different for
/// [sending] and [receiving]. The decrypted content is a protobuf-encoded
/// `UnidentifiedSenderMessage.Message` from `sealed_sender.proto`.
///
/// The public key used in Sealed Sender v2 is always a Curve25519 DJB key.
///
/// [sending]: #sent-messages
/// [receiving]: #received-messages
///
/// ## The version byte
///
/// Sealed sender messages (v1 and v2) in serialized form begin with a version [byte][u8]. This byte
/// has the form:
///
/// ```text
/// (requiredVersion << 4) | currentVersion
/// ```
///
/// v1 messages thus have a version byte of `0x11`. v2 messages have a version byte of `0x22` or
/// `0x23`. A hypothetical version byte `0x34` would indicate a message encoded as Sealed Sender v4,
/// but decodable by any client that supports Sealed Sender v3.
///
/// ## Received messages
///
/// ```text
/// ReceivedMessage {
///     version_byte: u8,
///     c: [u8; 32],
///     at: [u8; 16],
///     e_pub: [u8; 32],
///     message: [u8] // remaining bytes
/// }
/// ```
///
/// Each individual Sealed Sender message received from the server is decoded in the Signal client
/// by calling [`sealed_sender_decrypt`].
///
/// ## Sent messages
///
/// ```text
/// SentMessage {
///     version_byte: u8,
///     count: varint,
///     recipients: [PerRecipientData | ExcludedRecipient; count],
///     e_pub: [u8; 32],
///     message: [u8] // remaining bytes
/// }
///
/// PerRecipientData {
///     recipient: Recipient,
///     devices: [DeviceList], // last element's has_more = 0
///     c: [u8; 32],
///     at: [u8; 16],
/// }
///
/// ExcludedRecipient {
///     recipient: Recipient,
///     no_devices_marker: u8 = 0, // never a valid device ID
/// }
///
/// DeviceList {
///     device_id: u8,
///     has_more: u1, // high bit of following field
///     unused: u1,   // high bit of following field
///     registration_id: u14,
/// }
///
/// Recipient {
///     service_id_fixed_width_binary: [u8; 17],
/// }
/// ```
///
/// The varint encoding used is the same as [protobuf's][varint]. Values are unsigned.
/// Fixed-width-binary encoding is used for the [ServiceId] values.
/// Fixed-width integers are unaligned and in network byte order (big-endian).
///
/// [varint]: https://developers.google.com/protocol-buffers/docs/encoding#varints
pub async fn sealed_sender_multi_recipient_encrypt<
    R: Rng + CryptoRng,
    X: IntoIterator<Item = ServiceId>,
>(
    destinations: &[&ProtocolAddress],
    destination_sessions: &[&SessionRecord],
    excluded_recipients: X,
    usmc: &UnidentifiedSenderMessageContent,
    identity_store: &dyn IdentityKeyStore,
    rng: &mut R,
) -> Result<Vec<u8>>
where
    X::IntoIter: ExactSizeIterator,
{
    sealed_sender_multi_recipient_encrypt_impl(
        destinations,
        destination_sessions,
        excluded_recipients,
        usmc,
        identity_store,
        rng,
    )
    .await
}

async fn sealed_sender_multi_recipient_encrypt_impl<
    R: Rng + CryptoRng,
    X: IntoIterator<Item = ServiceId>,
>(
    destinations: &[&ProtocolAddress],
    destination_sessions: &[&SessionRecord],
    excluded_recipients: X,
    usmc: &UnidentifiedSenderMessageContent,
    identity_store: &dyn IdentityKeyStore,
    rng: &mut R,
) -> Result<Vec<u8>>
where
    X::IntoIter: ExactSizeIterator,
{
    if destinations.len() != destination_sessions.len() {
        return Err(SignalProtocolError::InvalidArgument(
            "must have the same number of destination sessions as addresses".to_string(),
        ));
    }

    let excluded_recipients = excluded_recipients.into_iter();
    let our_identity = identity_store.get_identity_key_pair().await?;

    let m: [u8; sealed_sender_v2::MESSAGE_KEY_LEN] = rng.gen();
    let keys = sealed_sender_v2::DerivedKeys::new(&m);
    let e = keys.derive_e();
    let e_pub = &e.public_key;

    // Encrypt the shared ciphertext using AES-GCM-SIV.
    let ciphertext = {
        let mut ciphertext = usmc.serialized()?.to_vec();
        let symmetric_authentication_tag = Aes256GcmSiv::new(&keys.derive_k().into())
            .encrypt_in_place_detached(
                // There's no nonce because the key is already one-use.
                &aes_gcm_siv::Nonce::default(),
                // And there's no associated data.
                &[],
                &mut ciphertext,
            )
            .expect("AES-GCM-SIV encryption should not fail with a just-computed key");
        // AES-GCM-SIV expects the authentication tag to be at the end of the ciphertext
        // when decrypting.
        ciphertext.extend_from_slice(&symmetric_authentication_tag);
        ciphertext
    };

    // Group the destinations by name, and fetch identity keys once for each name. This optimizes
    // for the common case where all of a recipient's devices are included contiguously in the
    // destination list. (If the caller *doesn't* do this, that's on them; the message will still be
    // valid but some key material will be redundantly computed and encoded in the output.)
    let identity_keys_and_ranges: Vec<(IdentityKey, Range<usize>)> = {
        let mut identity_keys_and_ranges = vec![];
        for (_, mut next_group) in &destinations
            .iter()
            .enumerate()
            .chunk_by(|(_i, next)| next.name())
        {
            let (i, &destination) = next_group
                .next()
                .expect("at least one element in every group");
            // We can't put this before the call to `next()` because `count` consumes the rest of
            // the iterator.
            let count = 1 + next_group.count();
            let their_identity =
                identity_store
                    .get_identity(destination)
                    .await?
                    .ok_or_else(|| {
                        log::error!("missing identity key for {}", destination);
                        // Returned as a SessionNotFound error because (a) we don't have an identity
                        // error that includes the address, and (b) re-establishing the session should
                        // re-fetch the identity.
                        SignalProtocolError::SessionNotFound(destination.clone())
                    })?;
            identity_keys_and_ranges.push((their_identity, i..i + count));
        }
        identity_keys_and_ranges
    };

    // Next, fan out the work of generating the per-recipient to multiple cores, since we do two key
    // agreements per recipient (though not per device) and those are CPU-bound.

    // I know this looks complicated enough to pull out into a separate function altogether, but it
    // also depends on a bunch of local state: our identity, E and E_pub, and M.
    let serialize_recipient_destinations_into = |serialized: &mut Vec<u8>,
                                                 destinations: &[&ProtocolAddress],
                                                 sessions: &[&SessionRecord],
                                                 their_identity: &IdentityKey|
     -> Result<()> {
        let their_service_id = ServiceId::parse_from_service_id_string(destinations[0].name())
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument(format!(
                    "multi-recipient sealed sender requires recipients' ServiceId (not {})",
                    destinations[0].name()
                ))
            })?;

        serialized.extend_from_slice(&their_service_id.service_id_fixed_width_binary());

        debug_assert_eq!(
            destinations.len(),
            sessions.len(),
            "should be sliced with the same range"
        );
        let mut destinations_and_sessions = destinations.iter().zip(sessions);
        while let Some((&destination, session)) = destinations_and_sessions.next() {
            let their_registration_id = session.remote_registration_id().map_err(|_| {
                SignalProtocolError::InvalidState(
                    "sealed_sender_multi_recipient_encrypt",
                    format!(
                        concat!(
                            "cannot get registration ID from session with {} ",
                            "(maybe it was recently archived)"
                        ),
                        destination
                    ),
                )
            })?;
            if their_registration_id & u32::from(VALID_REGISTRATION_ID_MASK)
                != their_registration_id
            {
                return Err(SignalProtocolError::InvalidRegistrationId(
                    destination.clone(),
                    their_registration_id,
                ));
            }
            let mut their_registration_id =
                u16::try_from(their_registration_id).expect("just checked range");
            if destinations_and_sessions.len() > 0 {
                their_registration_id |= 0x8000;
            }

            let device_id: u32 = destination.device_id().into();
            if device_id == 0 || device_id > MAX_VALID_DEVICE_ID {
                return Err(SignalProtocolError::InvalidState(
                    "sealed_sender_multi_recipient_encrypt",
                    format!("destination {destination} has invalid device ID"),
                ));
            }
            serialized.push(device_id.try_into().expect("just checked range"));
            serialized.extend_from_slice(&their_registration_id.to_be_bytes());
        }

        let c_i = sealed_sender_v2::apply_agreement_xor(
            &e,
            their_identity.public_key(),
            Direction::Sending,
            &m,
        )?;
        serialized.extend_from_slice(&c_i);

        let at_i = sealed_sender_v2::compute_authentication_tag(
            &our_identity,
            their_identity,
            Direction::Sending,
            e_pub,
            &c_i,
        )?;
        serialized.extend_from_slice(&at_i);

        Ok(())
    };

    let process_chunk =
        |serialized: &mut Vec<u8>, chunk: &[(IdentityKey, Range<usize>)]| -> Result<()> {
            for (their_identity, destination_range) in chunk {
                let these_destinations = &destinations[destination_range.clone()];
                let these_sessions = &destination_sessions[destination_range.clone()];
                serialize_recipient_destinations_into(
                    serialized,
                    these_destinations,
                    these_sessions,
                    their_identity,
                )?;
            }
            Ok(())
        };

    let mut serialized: Vec<u8> = vec![SEALED_SENDER_V2_SERVICE_ID_FULL_VERSION];

    let count_of_recipients = identity_keys_and_ranges.len() + excluded_recipients.len();
    prost::encode_length_delimiter(count_of_recipients, &mut serialized)
        .expect("can always resize a Vec");

    // Fan out to N threads, like Rayon would. But don't bother for less than 6 items.
    let parallelism = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let chunk_size = std::cmp::max(6, identity_keys_and_ranges.len().div_ceil(parallelism));

    if parallelism == 1 || chunk_size >= identity_keys_and_ranges.len() {
        process_chunk(&mut serialized, &identity_keys_and_ranges)?;
    } else {
        let mut chunks = identity_keys_and_ranges.chunks(chunk_size);
        // We'll process the first chunk on the current thread once we've spawned all the others.
        let first_chunk = chunks.next().expect("at least one chunk, tested above");

        let mut all_outputs = Vec::new();
        all_outputs.resize_with(chunks.len(), || Ok(vec![]));

        rayon::scope(|scope| -> Result<()> {
            let mut outputs = &mut all_outputs[..];
            for chunk in chunks {
                let (next_output, remaining_outputs) = outputs
                    .split_first_mut()
                    .expect("as many outputs as remaining chunks");
                scope.spawn(|_| {
                    let mut serialized = vec![];
                    *next_output = process_chunk(&mut serialized, chunk).map(|_| serialized);
                });
                outputs = remaining_outputs;
            }

            process_chunk(&mut serialized, first_chunk)
        })?;

        for output in all_outputs {
            serialized.extend(output?);
        }
    }

    for excluded in excluded_recipients {
        serialized.extend_from_slice(&excluded.service_id_fixed_width_binary());
        serialized.push(0);
    }

    serialized.extend_from_slice(e_pub.public_key_bytes());
    serialized.extend_from_slice(&ciphertext);

    Ok(serialized)
}

/// Represents a single recipient in an SSv2 SentMessage.
///
/// See [`SealedSenderV2SentMessage`].
pub struct SealedSenderV2SentMessageRecipient<'a> {
    /// The recipient's devices and their registration IDs. May be empty.
    pub devices: Vec<(DeviceId, u16)>,
    /// A concatenation of the `C_i` and `AT_i` SSv2 fields for this recipient, or an empty slice if
    /// the recipient has no devices.
    c_and_at: &'a [u8],
}

/// A parsed representation of a Sealed Sender v2 SentMessage.
///
/// This only parses enough to fan out the message as a series of ReceivedMessages.
pub struct SealedSenderV2SentMessage<'a> {
    /// The full message, for calculating offsets.
    full_message: &'a [u8],
    /// The version byte at the head of the message.
    pub version: u8,
    /// The parsed list of recipients, grouped by ServiceId.
    ///
    /// The map is ordered by when a recipient first appears in the full message, even if they
    /// appear again later with more devices. This makes iteration over the full set of recipients
    /// deterministic.
    pub recipients: IndexMap<ServiceId, SealedSenderV2SentMessageRecipient<'a>>,
    /// A concatenation of the `e_pub` and `message` SSv2 fields for this recipient.
    shared_bytes: &'a [u8],
}

impl<'a> SealedSenderV2SentMessage<'a> {
    /// Parses the message, or produces an error if the message is invalid.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(SignalProtocolError::InvalidSealedSenderMessage(
                "Message was empty".to_owned(),
            ));
        }

        let version = data[0];
        if !matches!(
            version,
            SEALED_SENDER_V2_UUID_FULL_VERSION | SEALED_SENDER_V2_SERVICE_ID_FULL_VERSION
        ) {
            return Err(SignalProtocolError::UnknownSealedSenderVersion(version));
        }

        fn advance<'a, const N: usize>(buf: &mut &'a [u8]) -> Result<&'a [u8; N]> {
            if N > buf.len() {
                return Err(SignalProtocolError::InvalidProtobufEncoding);
            }
            // TODO: Replace with split_array_ref or split_first_chunk when stabilized.
            let (prefix, remaining) = buf.split_at(N);
            *buf = remaining;
            Ok(prefix.try_into().expect("checked length"))
        }
        fn decode_varint(buf: &mut &[u8]) -> Result<u32> {
            let result: usize = prost::decode_length_delimiter(*buf)
                .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
            *buf = &buf[prost::length_delimiter_len(result)..];
            result
                .try_into()
                .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)
        }

        let mut remaining = &data[1..];
        let recipient_count = decode_varint(&mut remaining)?
            .try_into()
            .unwrap_or(usize::MAX);

        // Cap our preallocated capacity; anything higher than this is *probably* a mistake, but
        // could just be a very large message.
        // (Callers can of course refuse to process messages with too many recipients.)
        let mut recipients: IndexMap<ServiceId, SealedSenderV2SentMessageRecipient<'a>> =
            IndexMap::with_capacity(std::cmp::min(recipient_count as usize, 6000));
        for _ in 0..recipient_count {
            let service_id = if version == SEALED_SENDER_V2_UUID_FULL_VERSION {
                // The original version of SSv2 assumed ACIs here, and only encoded the raw UUID.
                ServiceId::from(Aci::from_uuid_bytes(*advance::<
                    { std::mem::size_of::<uuid::Bytes>() },
                >(&mut remaining)?))
            } else {
                ServiceId::parse_from_service_id_fixed_width_binary(advance::<
                    { std::mem::size_of::<ServiceIdFixedWidthBinaryBytes>() },
                >(
                    &mut remaining
                )?)
                .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            };
            let mut devices = Vec::new();
            loop {
                let device_id: u32 = advance::<1>(&mut remaining)?[0].into();
                if device_id == 0 {
                    if !devices.is_empty() {
                        return Err(SignalProtocolError::InvalidProtobufEncoding);
                    }
                    break;
                }
                if device_id > MAX_VALID_DEVICE_ID {
                    return Err(SignalProtocolError::InvalidProtobufEncoding);
                }
                let registration_id_and_has_more =
                    u16::from_be_bytes(*advance::<2>(&mut remaining)?);
                devices.push((
                    device_id.into(),
                    registration_id_and_has_more & VALID_REGISTRATION_ID_MASK,
                ));
                let has_more = (registration_id_and_has_more & 0x8000) != 0;
                if !has_more {
                    break;
                }
            }

            let c_and_at: &[u8] = if devices.is_empty() {
                &[]
            } else {
                advance::<{ sealed_sender_v2::MESSAGE_KEY_LEN + sealed_sender_v2::AUTH_TAG_LEN }>(
                    &mut remaining,
                )?
            };

            match recipients.entry(service_id) {
                indexmap::map::Entry::Occupied(mut existing) => {
                    if existing.get().devices.is_empty() || devices.is_empty() {
                        return Err(SignalProtocolError::InvalidSealedSenderMessage(
                            "recipient redundantly encoded as empty".to_owned(),
                        ));
                    }
                    // We don't unique the recipient devices; the server is going to check this
                    // against the account's canonical list of devices anyway.
                    existing.get_mut().devices.extend(devices);
                    // Note that we don't check that c_and_at matches. Any case where it doesn't
                    // match would already result in a decryption error for at least one of the
                    // recipient's devices, though.
                }
                indexmap::map::Entry::Vacant(entry) => {
                    entry.insert(SealedSenderV2SentMessageRecipient { devices, c_and_at });
                }
            };
        }

        if remaining.len() < sealed_sender_v2::PUBLIC_KEY_LEN {
            return Err(SignalProtocolError::InvalidProtobufEncoding);
        }

        Ok(Self {
            full_message: data,
            version,
            recipients,
            shared_bytes: remaining,
        })
    }

    /// Returns a slice of slices that, when concatenated, form the ReceivedMessage appropriate for
    /// `recipient`.
    ///
    /// If `recipient` is not one of the recipients in `self`, the resulting message will not be
    /// decryptable.
    #[inline]
    pub fn received_message_parts_for_recipient(
        &self,
        recipient: &SealedSenderV2SentMessageRecipient<'a>,
    ) -> impl AsRef<[&[u8]]> {
        // Why not use `IntoIterator<Item = &[u8]>` as the result? Because the `concat` method on
        // slices is more efficient when the caller just wants a `Vec<u8>`.
        // Why use SEALED_SENDER_V2_UUID_FULL_VERSION as the version? Because the ReceivedMessage
        // format hasn't changed since then.
        [
            &[SEALED_SENDER_V2_UUID_FULL_VERSION],
            recipient.c_and_at,
            self.shared_bytes,
        ]
    }

    /// Returns the offset of `addr` within `self.full_message`, or `None` if `addr` does not lie
    /// within `self.full_message`.
    ///
    /// A stripped-down version of [a dormant Rust RFC][subslice-offset].
    ///
    /// [subslice-offset]: https://github.com/rust-lang/rfcs/pull/2796
    #[inline]
    fn offset_within_full_message(&self, addr: *const u8) -> Option<usize> {
        // Arithmetic on addresses is valid for offsets within a byte array.
        // If addr < start, we'll wrap around to a very large value, which will be out of range just
        // like if addr > end.
        let offset = (addr as usize).wrapping_sub(self.full_message.as_ptr() as usize);
        // We *do* want to allow the "one-past-the-end" offset here, because the offset might be
        // used as part of a range (e.g. 0..end).
        if offset <= self.full_message.len() {
            debug_assert!(
                offset == self.full_message.len() || std::ptr::eq(&self.full_message[offset], addr)
            );
            Some(offset)
        } else {
            None
        }
    }

    /// Returns the range within the full message of `recipient`'s user-specific key material.
    ///
    /// This can be concatenated as `[version, recipient_key_material, shared_bytes]` to produce a
    /// valid SSv2 ReceivedMessage, the payload delivered to recipients.
    ///
    /// **Panics** if `recipient` is not one of the recipients in `self`.
    pub fn range_for_recipient_key_material(
        &self,
        recipient: &SealedSenderV2SentMessageRecipient<'a>,
    ) -> Range<usize> {
        if recipient.c_and_at.is_empty() {
            return 0..0;
        }
        let offset = self
            .offset_within_full_message(recipient.c_and_at.as_ptr())
            .expect("'recipient' is not one of the recipients in this SealedSenderV2SentMessage");
        let end_offset = offset.saturating_add(recipient.c_and_at.len());
        assert!(
            end_offset <= self.full_message.len(),
            "invalid 'recipient' passed to range_for_recipient_key_material"
        );
        offset..end_offset
    }

    /// Returns the offset of the shared bytes within the full message.
    ///
    /// This can be concatenated as `[version, recipient_key_material, shared_bytes]` to produce a
    /// valid SSv2 ReceivedMessage, the payload delivered to recipients.
    pub fn offset_of_shared_bytes(&self) -> usize {
        debug_assert_eq!(
            self.full_message.as_ptr_range().end,
            self.shared_bytes.as_ptr_range().end,
            "SealedSenderV2SentMessage parsed incorrectly"
        );
        self.offset_within_full_message(self.shared_bytes.as_ptr())
            .expect("constructed correctly")
    }
}

/// Decrypt the payload of a sealed-sender message in either the v1 or v2 format.
///
/// [`sealed_sender_decrypt`] consumes the output of this method to validate the sender's identity
/// before decrypting the underlying message.
pub async fn sealed_sender_decrypt_to_usmc(
    ciphertext: &[u8],
    identity_store: &dyn IdentityKeyStore,
) -> Result<UnidentifiedSenderMessageContent> {
    let our_identity = identity_store.get_identity_key_pair().await?;

    match UnidentifiedSenderMessage::deserialize(ciphertext)? {
        UnidentifiedSenderMessage::V1 {
            ephemeral_public,
            encrypted_static,
            encrypted_message,
        } => {
            let eph_keys = sealed_sender_v1::EphemeralKeys::calculate(
                &our_identity.into(),
                &ephemeral_public,
                Direction::Receiving,
            )?;

            let message_key_bytes = match crypto::aes256_ctr_hmacsha256_decrypt(
                &encrypted_static,
                &eph_keys.cipher_key,
                &eph_keys.mac_key,
            ) {
                Ok(plaintext) => plaintext,
                Err(crypto::DecryptionError::BadKeyOrIv) => {
                    unreachable!("just derived these keys; they should be valid");
                }
                Err(crypto::DecryptionError::BadCiphertext(msg)) => {
                    log::error!("failed to decrypt sealed sender v1 message key: {}", msg);
                    return Err(SignalProtocolError::InvalidSealedSenderMessage(
                        "failed to decrypt sealed sender v1 message key".to_owned(),
                    ));
                }
            };

            let static_key = PublicKey::try_from(&message_key_bytes[..])?;

            let static_keys = sealed_sender_v1::StaticKeys::calculate(
                &our_identity,
                &static_key,
                &eph_keys.chain_key,
                &encrypted_static,
            )?;

            let message_bytes = match crypto::aes256_ctr_hmacsha256_decrypt(
                &encrypted_message,
                &static_keys.cipher_key,
                &static_keys.mac_key,
            ) {
                Ok(plaintext) => plaintext,
                Err(crypto::DecryptionError::BadKeyOrIv) => {
                    unreachable!("just derived these keys; they should be valid");
                }
                Err(crypto::DecryptionError::BadCiphertext(msg)) => {
                    log::error!(
                        "failed to decrypt sealed sender v1 message contents: {}",
                        msg
                    );
                    return Err(SignalProtocolError::InvalidSealedSenderMessage(
                        "failed to decrypt sealed sender v1 message contents".to_owned(),
                    ));
                }
            };

            let usmc = UnidentifiedSenderMessageContent::deserialize(&message_bytes)?;

            if !bool::from(message_key_bytes.ct_eq(&usmc.sender()?.key()?.serialize())) {
                return Err(SignalProtocolError::InvalidSealedSenderMessage(
                    "sender certificate key does not match message key".to_string(),
                ));
            }

            Ok(usmc)
        }
        UnidentifiedSenderMessage::V2 {
            ephemeral_public,
            encrypted_message_key,
            authentication_tag,
            encrypted_message,
        } => {
            let m = sealed_sender_v2::apply_agreement_xor(
                &our_identity.into(),
                &ephemeral_public,
                Direction::Receiving,
                encrypted_message_key,
            )?;

            let keys = sealed_sender_v2::DerivedKeys::new(&m);
            if !bool::from(keys.derive_e().public_key.ct_eq(&ephemeral_public)) {
                return Err(SignalProtocolError::InvalidSealedSenderMessage(
                    "derived ephemeral key did not match key provided in message".to_string(),
                ));
            }

            let mut message_bytes = Vec::from(encrypted_message);
            Aes256GcmSiv::new(&keys.derive_k().into())
                .decrypt_in_place(
                    // There's no nonce because the key is already one-use.
                    &aes_gcm_siv::Nonce::default(),
                    // And there's no associated data.
                    &[],
                    &mut message_bytes,
                )
                .map_err(|err| {
                    SignalProtocolError::InvalidSealedSenderMessage(format!(
                        "failed to decrypt inner message: {}",
                        err
                    ))
                })?;

            let usmc = UnidentifiedSenderMessageContent::deserialize(&message_bytes)?;

            let at = sealed_sender_v2::compute_authentication_tag(
                &our_identity,
                &usmc.sender()?.key()?.into(),
                Direction::Receiving,
                &ephemeral_public,
                encrypted_message_key,
            )?;
            if !bool::from(authentication_tag.ct_eq(&at)) {
                return Err(SignalProtocolError::InvalidSealedSenderMessage(
                    "sender certificate key does not match authentication tag".to_string(),
                ));
            }

            Ok(usmc)
        }
    }
}

#[derive(Debug)]
pub struct SealedSenderDecryptionResult {
    pub sender_uuid: String,
    pub sender_e164: Option<String>,
    pub device_id: DeviceId,
    pub message: Vec<u8>,
}

impl SealedSenderDecryptionResult {
    pub fn sender_uuid(&self) -> Result<&str> {
        Ok(self.sender_uuid.as_ref())
    }

    pub fn sender_e164(&self) -> Result<Option<&str>> {
        Ok(self.sender_e164.as_deref())
    }

    pub fn device_id(&self) -> Result<DeviceId> {
        Ok(self.device_id)
    }

    pub fn message(&self) -> Result<&[u8]> {
        Ok(self.message.as_ref())
    }
}

/// Decrypt a Sealed Sender message `ciphertext` in either the v1 or v2 format, validate its sender
/// certificate, and then decrypt the inner message payload.
///
/// This method calls [`sealed_sender_decrypt_to_usmc`] to extract the sender information, including
/// the embedded [`SenderCertificate`]. The sender certificate (signed by the [`ServerCertificate`])
/// is then validated against the `trust_root` baked into the client to ensure that the sender's
/// identity was not forged.
#[allow(clippy::too_many_arguments)]
pub async fn sealed_sender_decrypt(
    ciphertext: &[u8],
    trust_root: &PublicKey,
    timestamp: Timestamp,
    local_e164: Option<String>,
    local_uuid: String,
    local_device_id: DeviceId,
    identity_store: &mut dyn IdentityKeyStore,
    session_store: &mut dyn SessionStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &dyn SignedPreKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
) -> Result<SealedSenderDecryptionResult> {
    let usmc = sealed_sender_decrypt_to_usmc(ciphertext, identity_store).await?;

    if !usmc.sender()?.validate(trust_root, timestamp)? {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "trust root validation failed".to_string(),
        ));
    }

    let is_local_uuid = local_uuid == usmc.sender()?.sender_uuid()?;

    let is_local_e164 = match (local_e164, usmc.sender()?.sender_e164()?) {
        (Some(l), Some(s)) => l == s,
        (_, _) => false,
    };

    if (is_local_e164 || is_local_uuid) && usmc.sender()?.sender_device_id()? == local_device_id {
        return Err(SignalProtocolError::SealedSenderSelfSend);
    }

    let mut rng = rand::rngs::OsRng;

    let remote_address = ProtocolAddress::new(
        usmc.sender()?.sender_uuid()?.to_string(),
        usmc.sender()?.sender_device_id()?,
    );

    let message = match usmc.msg_type()? {
        CiphertextMessageType::Whisper => {
            let ctext = SignalMessage::try_from(usmc.contents()?)?;
            session_cipher::message_decrypt_signal(
                &ctext,
                &remote_address,
                session_store,
                identity_store,
                &mut rng,
            )
            .await?
        }
        CiphertextMessageType::PreKey => {
            let ctext = PreKeySignalMessage::try_from(usmc.contents()?)?;
            session_cipher::message_decrypt_prekey(
                &ctext,
                &remote_address,
                session_store,
                identity_store,
                pre_key_store,
                signed_pre_key_store,
                kyber_pre_key_store,
                &mut rng,
            )
            .await?
        }
        msg_type => {
            return Err(SignalProtocolError::InvalidMessage(
                msg_type,
                "unexpected message type for sealed_sender_decrypt",
            ));
        }
    };

    Ok(SealedSenderDecryptionResult {
        sender_uuid: usmc.sender()?.sender_uuid()?.to_string(),
        sender_e164: usmc.sender()?.sender_e164()?.map(|s| s.to_string()),
        device_id: usmc.sender()?.sender_device_id()?,
        message,
    })
}

#[test]
fn test_lossless_round_trip() -> Result<()> {
    let trust_root = PrivateKey::deserialize(&[0u8; 32])?;

    // To test a hypothetical addition of a new field:
    //
    // Step 1: temporarily add a new field to the .proto.
    //
    //    --- a/rust/protocol/src/proto/sealed_sender.proto
    //    +++ b/rust/protocol/src/proto/sealed_sender.proto
    //    @@ -26,3 +26,4 @@ message SenderCertificate {
    //             optional bytes             identityKey   = 4;
    //             optional ServerCertificate signer        = 5;
    //    +        optional string someFakeField = 999;
    //     }
    //
    // Step 2: Add `some_fake_field: None` to the above construction of
    // proto::sealed_sender::sender_certificate::Certificate.
    //
    // Step 3: Serialize and print out the new fixture data (uncomment the following)
    //
    // let mut rng = rand::rngs::OsRng;
    // let server_key = KeyPair::generate(&mut rng);
    // let sender_key = KeyPair::generate(&mut rng);
    //
    // let server_cert =
    //     ServerCertificate::new(1, server_key.public_key, &trust_root, &mut rng)?;
    //
    // let sender_cert = proto::sealed_sender::sender_certificate::Certificate {
    //     sender_uuid: Some("aaaaaaaa-7000-11eb-b32a-33b8a8a487a6".to_string()),
    //     sender_e164: None,
    //     sender_device: Some(1),
    //     expires: Some(31337),
    //     identity_key: Some(sender_key.public_key.serialize().to_vec()),
    //     signer: Some(server_cert.to_protobuf()?),
    //     some_fake_field: Some("crashing right down".to_string()),
    // };
    //
    // eprintln!("<SNIP>");
    // let serialized_certificate_data = sender_cert.encode_to_vec();
    // let certificate_data_encoded = hex::encode(&serialized_certificate_data);
    // eprintln!("let certificate_data_encoded = \"{}\";", certificate_data_encoded);
    //
    // let certificate_signature = server_key.calculate_signature(&serialized_certificate_data, &mut rng)?;
    // let certificate_signature_encoded = hex::encode(certificate_signature);
    // eprintln!("let certificate_signature_encoded = \"{}\";", certificate_signature_encoded);

    // Step 4: update the following *_encoded fixture data with the new values from above.
    let certificate_data_encoded = "100119697a0000000000002221056c9d1f8deb82b9a898f9c277a1b74989ec009afb5c0acb5e8e69e3d5ca29d6322a690a2508011221053b03ca070e6f6b2f271d32f27321689cdf4e59b106c10b58fbe15063ed868a5a124024bc92954e52ad1a105b5bda85c9db410dcfeb42a671b45a523b3a46e9594a8bde0efc671d8e8e046b32c67f59b80a46ffdf24071850779bc21325107902af89322461616161616161612d373030302d313165622d623332612d333362386138613438376136ba3e136372617368696e6720726967687420646f776e";
    let certificate_signature_encoded = "a22d8f86f5d00794f319add821e342c6ffffb6b34f741e569f8b321ab0255f2d1757ecf648e53a3602cae8f09b3fc80dcf27534d67efd272b6739afc31f75c8c";

    // The rest of the test should be stable.
    let certificate_data = hex::decode(certificate_data_encoded).expect("valid hex");
    let certificate_signature = hex::decode(certificate_signature_encoded).expect("valid hex");

    let sender_certificate_data = proto::sealed_sender::SenderCertificate {
        certificate: Some(certificate_data),
        signature: Some(certificate_signature),
    };

    let sender_certificate =
        SenderCertificate::deserialize(&sender_certificate_data.encode_to_vec())?;
    assert!(sender_certificate.validate(
        &trust_root.public_key()?,
        Timestamp::from_epoch_millis(31336)
    )?);
    Ok(())
}
