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
