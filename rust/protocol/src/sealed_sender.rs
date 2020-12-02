//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::crypto;
use crate::error::{Result, SignalProtocolError};
use crate::kdf::HKDF;
use crate::proto;
use crate::session_cipher;
use crate::{
    message_encrypt, CiphertextMessageType, Context, IdentityKeyStore, KeyPair,
    PreKeySignalMessage, PreKeyStore, PrivateKey, ProtocolAddress, PublicKey, SessionStore,
    SignalMessage, SignedPreKeyStore,
};
use prost::Message;
use rand::{CryptoRng, Rng};
use std::convert::TryFrom;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone)]
pub struct ServerCertificate {
    serialized: Vec<u8>,
    key_id: u32,
    key: PublicKey,
    certificate: Vec<u8>,
    signature: Vec<u8>,
}

impl ServerCertificate {
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let pb = proto::sealed_sender::ServerCertificate::decode(data)?;

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
            proto::sealed_sender::server_certificate::Certificate::decode(certificate.as_ref())?;
        let key = PublicKey::deserialize(
            &certificate_data
                .key
                .ok_or(SignalProtocolError::InvalidProtobufEncoding)?,
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

        let mut certificate = vec![];
        certificate_pb.encode(&mut certificate)?;

        let signature = trust_root.calculate_signature(&certificate, rng)?.to_vec();

        let mut serialized = vec![];
        let pb = proto::sealed_sender::ServerCertificate {
            certificate: Some(certificate.clone()),
            signature: Some(signature.clone()),
        };
        pb.encode(&mut serialized)?;

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
        trust_root.verify_signature(&self.certificate, &self.signature)
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
    sender_device_id: u32,
    sender_uuid: Option<String>,
    sender_e164: Option<String>,
    expiration: u64,
    serialized: Vec<u8>,
    certificate: Vec<u8>,
    signature: Vec<u8>,
}

impl SenderCertificate {
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let pb = proto::sealed_sender::SenderCertificate::decode(data)?;
        let certificate = pb
            .certificate
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signature = pb
            .signature
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let certificate_data =
            proto::sealed_sender::sender_certificate::Certificate::decode(certificate.as_ref())?;

        let sender_device_id = certificate_data
            .sender_device
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let expiration = certificate_data
            .expires
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signer_pb = certificate_data
            .signer
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender_uuid = certificate_data.sender_uuid;
        let sender_e164 = certificate_data.sender_e164;

        let key = PublicKey::deserialize(
            &certificate_data
                .identity_key
                .ok_or(SignalProtocolError::InvalidProtobufEncoding)?,
        )?;

        if sender_uuid.is_none() && sender_e164.is_none() {
            return Err(SignalProtocolError::InvalidProtobufEncoding);
        }

        let mut signer_bits = vec![];
        signer_pb.encode(&mut signer_bits)?;
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
        sender_uuid: Option<String>,
        sender_e164: Option<String>,
        key: PublicKey,
        sender_device_id: u32,
        expiration: u64,
        signer: ServerCertificate,
        signer_key: &PrivateKey,
        rng: &mut R,
    ) -> Result<Self> {
        let certificate_pb = proto::sealed_sender::sender_certificate::Certificate {
            sender_uuid: sender_uuid.clone(),
            sender_e164: sender_e164.clone(),
            sender_device: Some(sender_device_id),
            expires: Some(expiration),
            identity_key: Some(key.serialize().to_vec()),
            signer: Some(signer.to_protobuf()?),
        };

        let mut certificate = vec![];
        certificate_pb.encode(&mut certificate)?;

        let signature = signer_key.calculate_signature(&certificate, rng)?.to_vec();

        let pb = proto::sealed_sender::SenderCertificate {
            certificate: Some(certificate.clone()),
            signature: Some(signature.clone()),
        };
        let mut serialized = vec![];
        pb.encode(&mut serialized)?;

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

    pub(crate) fn from_protobuf(pb: &proto::sealed_sender::SenderCertificate) -> Result<Self> {
        let mut bits = vec![];
        pb.encode(&mut bits)?;
        Self::deserialize(&bits)
    }

    pub(crate) fn to_protobuf(&self) -> Result<proto::sealed_sender::SenderCertificate> {
        Ok(proto::sealed_sender::SenderCertificate {
            certificate: Some(self.certificate.clone()),
            signature: Some(self.signature.clone()),
        })
    }

    pub fn validate(&self, trust_root: &PublicKey, validation_time: u64) -> Result<bool> {
        if !self.signer.validate(&trust_root)? {
            return Ok(false);
        }

        if !self
            .signer
            .public_key()?
            .verify_signature(&self.certificate, &self.signature)?
        {
            return Ok(false);
        }

        if validation_time > self.expiration {
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

    pub fn sender_device_id(&self) -> Result<u32> {
        Ok(self.sender_device_id)
    }

    pub fn sender_uuid(&self) -> Result<Option<&str>> {
        Ok(self.sender_uuid.as_deref())
    }

    pub fn sender_e164(&self) -> Result<Option<&str>> {
        Ok(self.sender_e164.as_deref())
    }

    pub fn expiration(&self) -> Result<u64> {
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

    pub async fn preferred_address(
        &self,
        session_store: &dyn SessionStore,
        ctx: Context,
    ) -> Result<ProtocolAddress> {
        if let Some(uuid) = self.sender_uuid()? {
            let uuid_address = ProtocolAddress::new(uuid.to_owned(), self.sender_device_id()?);
            if session_store
                .load_session(&uuid_address, ctx)
                .await?
                .is_some()
            {
                return Ok(uuid_address);
            }
        }

        if let Some(e164) = self.sender_e164()? {
            let e164_address = ProtocolAddress::new(e164.to_owned(), self.sender_device_id()?);
            if session_store
                .load_session(&e164_address, ctx)
                .await?
                .is_some()
            {
                return Ok(e164_address);
            }
        }

        /*
         * This logic of preferring e164 over uuid comes from Java, but seems incorrect.
         */
        let best_address = match (self.sender_e164()?, self.sender_uuid()?) {
            (Some(e164), _) => e164.to_owned(),
            (None, Some(uuid)) => uuid.to_owned(),
            (None, None) => {
                return Err(SignalProtocolError::InvalidSealedSenderMessage(
                    "No sender in sender cert".to_owned(),
                ))
            }
        };

        Ok(ProtocolAddress::new(best_address, self.sender_device_id()?))
    }
}

pub struct UnidentifiedSenderMessageContent {
    serialized: Vec<u8>,
    contents: Vec<u8>,
    sender: SenderCertificate,
    msg_type: CiphertextMessageType,
}

impl UnidentifiedSenderMessageContent {
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let pb = proto::sealed_sender::unidentified_sender_message::Message::decode(data)?;

        let msg_type = pb
            .r#type
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender = pb
            .sender_certificate
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let contents = pb
            .content
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

        let msg_type = match msg_type {
            1 => Ok(CiphertextMessageType::PreKey),
            2 => Ok(CiphertextMessageType::Whisper),
            _ => Err(SignalProtocolError::InvalidProtobufEncoding),
        }?;

        let sender = SenderCertificate::from_protobuf(&sender)?;

        let serialized = data.to_vec();

        Ok(Self {
            serialized,
            contents,
            sender,
            msg_type,
        })
    }

    pub fn new(
        msg_type: CiphertextMessageType,
        sender: SenderCertificate,
        contents: Vec<u8>,
    ) -> Result<Self> {
        let proto_msg_type = match msg_type {
            CiphertextMessageType::PreKey => Ok(1),
            CiphertextMessageType::Whisper => Ok(2),
            _ => Err(SignalProtocolError::InvalidProtobufEncoding),
        }?;
        let msg = proto::sealed_sender::unidentified_sender_message::Message {
            content: Some(contents.clone()),
            r#type: Some(proto_msg_type),
            sender_certificate: Some(sender.to_protobuf()?),
        };

        let mut serialized = vec![];
        msg.encode(&mut serialized)?;

        // serialize it
        Ok(Self {
            msg_type,
            sender,
            contents,
            serialized,
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

    pub fn serialized(&self) -> Result<&[u8]> {
        Ok(&self.serialized)
    }
}

pub struct UnidentifiedSenderMessage {
    version: u8,
    ephemeral_public: PublicKey,
    encrypted_static: Vec<u8>,
    encrypted_message: Vec<u8>,
    serialized: Vec<u8>,
}

const SEALED_SENDER_VERSION: u8 = 1;

impl UnidentifiedSenderMessage {
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(SignalProtocolError::InvalidSealedSenderMessage(
                "Message was empty".to_owned(),
            ));
        }
        let version = data[0] >> 4;

        if version > SEALED_SENDER_VERSION {
            // XXX should we really be accepted version == 0 here?
            return Err(SignalProtocolError::UnknownSealedSenderVersion(version));
        }

        let pb = proto::sealed_sender::UnidentifiedSenderMessage::decode(&data[1..])?;

        let ephemeral_public = pb
            .ephemeral_public
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let encrypted_static = pb
            .encrypted_static
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let encrypted_message = pb
            .encrypted_message
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

        let ephemeral_public = PublicKey::deserialize(&ephemeral_public)?;

        let serialized = data.to_vec();

        Ok(Self {
            version,
            ephemeral_public,
            encrypted_static,
            encrypted_message,
            serialized,
        })
    }

    pub fn new(
        ephemeral_public: PublicKey,
        encrypted_static: Vec<u8>,
        encrypted_message: Vec<u8>,
    ) -> Result<Self> {
        let version = SEALED_SENDER_VERSION;
        let mut serialized = vec![];
        serialized.push(version | (version << 4));
        let pb = proto::sealed_sender::UnidentifiedSenderMessage {
            ephemeral_public: Some(ephemeral_public.serialize().to_vec()),
            encrypted_static: Some(encrypted_static.clone()),
            encrypted_message: Some(encrypted_message.clone()),
        };
        pb.encode(&mut serialized)?; // appends to buffer

        Ok(Self {
            version,
            ephemeral_public,
            encrypted_static,
            encrypted_message,
            serialized,
        })
    }

    pub fn version(&self) -> Result<u8> {
        Ok(self.version)
    }

    pub fn ephemeral_public(&self) -> Result<PublicKey> {
        Ok(self.ephemeral_public)
    }

    pub fn encrypted_static(&self) -> Result<&[u8]> {
        Ok(&self.encrypted_static)
    }

    pub fn encrypted_message(&self) -> Result<&[u8]> {
        Ok(&self.encrypted_message)
    }

    pub fn serialized(&self) -> Result<&[u8]> {
        Ok(&self.serialized)
    }
}

struct EphemeralKeys {
    derived_values: Box<[u8]>,
}

impl EphemeralKeys {
    pub fn calculate(
        their_public: &PublicKey,
        our_public: &PublicKey,
        our_private: &PrivateKey,
        sending: bool,
    ) -> Result<Self> {
        let mut ephemeral_salt = Vec::with_capacity(2 * 32 + 20);
        ephemeral_salt.extend_from_slice("UnidentifiedDelivery".as_bytes());

        if sending {
            ephemeral_salt.extend_from_slice(&their_public.serialize());
        }
        ephemeral_salt.extend_from_slice(&our_public.serialize());
        if !sending {
            ephemeral_salt.extend_from_slice(&their_public.serialize());
        }

        let shared_secret = our_private.calculate_agreement(their_public)?;
        let kdf = HKDF::new(3)?;
        let derived_values = kdf.derive_salted_secrets(&shared_secret, &ephemeral_salt, &[], 96)?;

        Ok(Self { derived_values })
    }

    fn chain_key(&self) -> Result<&[u8]> {
        Ok(&self.derived_values[0..32])
    }

    fn cipher_key(&self) -> Result<&[u8]> {
        Ok(&self.derived_values[32..64])
    }

    fn mac_key(&self) -> Result<&[u8]> {
        Ok(&self.derived_values[64..96])
    }
}

struct StaticKeys {
    derived_values: Box<[u8]>,
}
impl StaticKeys {
    pub fn calculate(
        their_public: &PublicKey,
        our_private: &PrivateKey,
        chain_key: &[u8],
        ctext: &[u8],
    ) -> Result<Self> {
        let mut salt = Vec::with_capacity(chain_key.len() + ctext.len());
        salt.extend_from_slice(chain_key);
        salt.extend_from_slice(ctext);

        let shared_secret = our_private.calculate_agreement(their_public)?;
        let kdf = HKDF::new(3)?;
        // 96 bytes are derived but the first 32 are discarded/unused
        let derived_values = kdf.derive_salted_secrets(&shared_secret, &salt, &[], 96)?;

        Ok(Self { derived_values })
    }

    fn cipher_key(&self) -> Result<&[u8]> {
        Ok(&self.derived_values[32..64])
    }

    fn mac_key(&self) -> Result<&[u8]> {
        Ok(&self.derived_values[64..96])
    }
}

pub async fn sealed_sender_encrypt<R: Rng + CryptoRng>(
    destination: &ProtocolAddress,
    sender_cert: &SenderCertificate,
    ptext: &[u8],
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    ctx: Context,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let message = message_encrypt(ptext, destination, session_store, identity_store, ctx).await?;

    let our_identity = identity_store.get_identity_key_pair(ctx).await?;
    let their_identity = identity_store
        .get_identity(destination, ctx)
        .await?
        .ok_or(SignalProtocolError::SessionNotFound)?;

    let ephemeral = KeyPair::generate(rng);

    let eph_keys = EphemeralKeys::calculate(
        their_identity.public_key(),
        &ephemeral.public_key,
        &ephemeral.private_key,
        true,
    )?;

    let static_key_ctext = crypto::aes256_ctr_hmacsha256_encrypt(
        &our_identity.public_key().serialize(),
        &eph_keys.cipher_key()?,
        &eph_keys.mac_key()?,
    )?;

    let static_keys = StaticKeys::calculate(
        their_identity.public_key(),
        our_identity.private_key(),
        eph_keys.chain_key()?,
        &static_key_ctext,
    )?;

    let usmc = UnidentifiedSenderMessageContent::new(
        message.message_type(),
        sender_cert.clone(),
        message.serialize().to_vec(),
    )?;
    let message_data = crypto::aes256_ctr_hmacsha256_encrypt(
        usmc.serialized()?,
        &static_keys.cipher_key()?,
        &static_keys.mac_key()?,
    )?;

    Ok(
        UnidentifiedSenderMessage::new(ephemeral.public_key, static_key_ctext, message_data)?
            .serialized()?
            .to_vec(),
    )
}

pub async fn sealed_sender_decrypt_to_usmc(
    ciphertext: &[u8],
    identity_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<UnidentifiedSenderMessageContent> {
    let our_identity = identity_store.get_identity_key_pair(ctx).await?;
    let usm = UnidentifiedSenderMessage::deserialize(ciphertext)?;

    let eph_keys = EphemeralKeys::calculate(
        &usm.ephemeral_public()?,
        &our_identity.public_key(),
        &our_identity.private_key(),
        false,
    )?;

    let static_key_bytes = crypto::aes256_ctr_hmacsha256_decrypt(
        usm.encrypted_static()?,
        &eph_keys.cipher_key()?,
        &eph_keys.mac_key()?,
    )?;

    let static_key = PublicKey::deserialize(&static_key_bytes)?;

    let static_keys = StaticKeys::calculate(
        &static_key,
        our_identity.private_key(),
        eph_keys.chain_key()?,
        usm.encrypted_static()?,
    )?;

    let message_bytes = crypto::aes256_ctr_hmacsha256_decrypt(
        usm.encrypted_message()?,
        &static_keys.cipher_key()?,
        &static_keys.mac_key()?,
    )?;

    let usmc = UnidentifiedSenderMessageContent::deserialize(&message_bytes)?;

    if !bool::from(static_key_bytes.ct_eq(&usmc.sender()?.key()?.serialize())) {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "sender certificate key does not match message key".to_string(),
        ));
    }

    Ok(usmc)
}

#[derive(Debug)]
pub struct SealedSenderDecryptionResult {
    pub sender_uuid: Option<String>,
    pub sender_e164: Option<String>,
    pub device_id: u32,
    pub message: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub async fn sealed_sender_decrypt(
    ciphertext: &[u8],
    trust_root: &PublicKey,
    timestamp: u64,
    local_e164: Option<String>,
    local_uuid: Option<String>,
    local_device_id: u32,
    identity_store: &mut dyn IdentityKeyStore,
    session_store: &mut dyn SessionStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &mut dyn SignedPreKeyStore,
    ctx: Context,
) -> Result<SealedSenderDecryptionResult> {
    let usmc = sealed_sender_decrypt_to_usmc(ciphertext, identity_store, ctx).await?;

    if !usmc.sender()?.validate(trust_root, timestamp)? {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "trust root validation failed".to_string(),
        ));
    }

    let is_local_e164 = match (local_e164, usmc.sender()?.sender_e164()?) {
        (Some(l), Some(s)) => l == s,
        (_, _) => false,
    };

    let is_local_uuid = match (local_uuid, usmc.sender()?.sender_uuid()?) {
        (Some(l), Some(s)) => l == s,
        (_, _) => false,
    };

    if (is_local_e164 || is_local_uuid) && usmc.sender()?.sender_device_id()? == local_device_id {
        return Err(SignalProtocolError::SealedSenderSelfSend);
    }

    let mut rng = rand::rngs::OsRng;

    let remote_address = usmc.sender()?.preferred_address(session_store, ctx).await?;

    let message = match usmc.msg_type()? {
        CiphertextMessageType::Whisper => {
            let ctext = SignalMessage::try_from(usmc.contents()?)?;
            session_cipher::message_decrypt_signal(
                &ctext,
                &remote_address,
                session_store,
                identity_store,
                &mut rng,
                ctx,
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
                &mut rng,
                ctx,
            )
            .await?
        }
        _ => {
            return Err(SignalProtocolError::InvalidSealedSenderMessage(
                "Unknown message type".to_owned(),
            ))
        }
    };

    Ok(SealedSenderDecryptionResult {
        sender_uuid: usmc.sender()?.sender_uuid()?.map(|s| s.to_string()),
        sender_e164: usmc.sender()?.sender_e164()?.map(|s| s.to_string()),
        device_id: usmc.sender()?.sender_device_id()?,
        message,
    })
}
