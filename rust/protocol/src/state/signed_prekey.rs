//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::proto::storage::SignedPreKeyRecordStructure;
use crate::{kem, KeyPair, PrivateKey, PublicKey, Result, SignalProtocolError};

use prost::Message;

use std::convert::AsRef;
use std::fmt;

/// A unique identifier selecting among this client's known signed pre-keys.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SignedPreKeyId(u32);

impl From<u32> for SignedPreKeyId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<SignedPreKeyId> for u32 {
    fn from(value: SignedPreKeyId) -> Self {
        value.0
    }
}

impl fmt::Display for SignedPreKeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct SignedPreKeyRecord {
    signed_pre_key: SignedPreKeyRecordStructure,
}

impl SignedPreKeyRecord {
    pub fn private_key(&self) -> Result<PrivateKey> {
        PrivateKey::deserialize(&self.get_storage().private_key)
    }
}

impl GenericSignedPreKey for SignedPreKeyRecord {
    type KeyPair = KeyPair;
    type Id = SignedPreKeyId;

    fn get_storage(&self) -> &SignedPreKeyRecordStructure {
        &self.signed_pre_key
    }

    fn from_storage(storage: SignedPreKeyRecordStructure) -> Self {
        Self {
            signed_pre_key: storage,
        }
    }
}

pub trait GenericSignedPreKey {
    type KeyPair: KeyPairSerde;
    type Id: From<u32> + Into<u32>;

    fn get_storage(&self) -> &SignedPreKeyRecordStructure;
    fn from_storage(storage: SignedPreKeyRecordStructure) -> Self;

    fn new(id: Self::Id, timestamp: u64, key_pair: &Self::KeyPair, signature: &[u8]) -> Self
    where
        Self: Sized,
    {
        let public_key = key_pair.get_public().serialize();
        let private_key = key_pair.get_private().serialize();
        let signature = signature.to_vec();
        Self::from_storage(SignedPreKeyRecordStructure {
            id: id.into(),
            timestamp,
            public_key,
            private_key,
            signature,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.get_storage().encode_to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self::from_storage(
            SignedPreKeyRecordStructure::decode(data)
                .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?,
        ))
    }

    fn id(&self) -> Result<Self::Id> {
        Ok(self.get_storage().id.into())
    }

    fn timestamp(&self) -> Result<u64> {
        Ok(self.get_storage().timestamp)
    }

    fn signature(&self) -> Result<Vec<u8>> {
        Ok(self.get_storage().signature.clone())
    }

    fn public_key(&self) -> Result<<Self::KeyPair as KeyPairSerde>::PublicKey> {
        <Self::KeyPair as KeyPairSerde>::PublicKey::deserialize(&self.get_storage().public_key)
    }

    fn key_pair(&self) -> Result<Self::KeyPair> {
        Self::KeyPair::from_public_and_private(
            &self.get_storage().public_key,
            &self.get_storage().private_key,
        )
    }
}

pub trait KeySerde {
    fn serialize(&self) -> Vec<u8>;
    fn deserialize<T: AsRef<[u8]>>(bytes: T) -> Result<Self>
    where
        Self: Sized;
}

pub trait KeyPairSerde {
    type PublicKey: KeySerde;
    type PrivateKey: KeySerde;
    fn from_public_and_private(public_key: &[u8], private_key: &[u8]) -> Result<Self>
    where
        Self: Sized;
    fn get_public(&self) -> &Self::PublicKey;
    fn get_private(&self) -> &Self::PrivateKey;
}

impl KeySerde for PublicKey {
    fn serialize(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }

    fn deserialize<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        Self::deserialize(bytes.as_ref())
    }
}

impl KeySerde for PrivateKey {
    fn serialize(&self) -> Vec<u8> {
        self.serialize()
    }

    fn deserialize<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        Self::deserialize(bytes.as_ref())
    }
}

impl KeySerde for kem::PublicKey {
    fn serialize(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }

    fn deserialize<T: AsRef<[u8]>>(bytes: T) -> Result<Self>
    where
        Self: Sized,
    {
        Self::deserialize(bytes.as_ref())
    }
}

impl KeySerde for kem::SecretKey {
    fn serialize(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }
    fn deserialize<T: AsRef<[u8]>>(bytes: T) -> Result<Self>
    where
        Self: Sized,
    {
        Self::deserialize(bytes.as_ref())
    }
}

impl KeyPairSerde for KeyPair {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;

    fn from_public_and_private(public_key: &[u8], private_key: &[u8]) -> Result<Self> {
        KeyPair::from_public_and_private(public_key, private_key)
    }

    fn get_public(&self) -> &PublicKey {
        &self.public_key
    }

    fn get_private(&self) -> &PrivateKey {
        &self.private_key
    }
}

impl KeyPairSerde for kem::KeyPair {
    type PublicKey = kem::PublicKey;
    type PrivateKey = kem::SecretKey;

    fn from_public_and_private(public_key: &[u8], private_key: &[u8]) -> Result<Self> {
        kem::KeyPair::from_public_and_private(public_key, private_key)
    }

    fn get_public(&self) -> &kem::PublicKey {
        &self.public_key
    }

    fn get_private(&self) -> &kem::SecretKey {
        &self.secret_key
    }
}
