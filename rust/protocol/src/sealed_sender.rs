//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::error::{Result, SignalProtocolError};
use crate::proto;
use crate::PublicKey;
use prost::Message;

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

    pub fn new<R: Rng + CryptoRng>(key_id: u32, key: PublicKey, trust_root: &PrivateKey, rng: &mut R) -> Result<Self> {
        let certificate_pb = proto::sealed_sender::server_certificate::Certificate {
            id: Some(key_id),
            key: Some(key.serialize().to_vec())
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

    pub fn new<R: Rng + CryptoRng>(sender_uuid: Option<String>,
                                   sender_e164: Option<String>,
                                   key: PublicKey,
                                   sender_device_id: u32,
                                   expiration: u64,
                                   signer: ServerCertificate,
                                   signer_key: &PrivateKey,
                                   rng: &mut R) -> Result<Self> {

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
}

pub struct UnidentifiedSenderMessageContent {
    serialized: Vec<u8>,
    contents: Vec<u8>,
    sender: SenderCertificate,
    msg_type: u8,
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
            1 => Ok(3),
            2 => Ok(2),
            3 => Ok(3),
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

    pub fn new(msg_type: u8, sender: SenderCertificate, contents: Vec<u8>) -> Result<Self> {
        let msg = proto::sealed_sender::unidentified_sender_message::Message {
            content: Some(contents.clone()),
            r#type: Some(msg_type as _),
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

    pub fn msg_type(&self) -> Result<u8> {
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
        if data.len() == 0 {
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

