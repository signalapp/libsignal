//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::proto::storage::PreKeyRecordStructure;
use crate::{KeyPair, PrivateKey, PublicKey, Result};
use prost::Message;

pub type PreKeyId = u32;

#[derive(Debug, Clone)]
pub struct PreKeyRecord {
    pre_key: PreKeyRecordStructure,
}

impl PreKeyRecord {
    pub fn new(id: PreKeyId, key: &KeyPair) -> Self {
        let public_key = key.public_key.serialize().to_vec();
        let private_key = key.private_key.serialize().to_vec();
        Self {
            pre_key: PreKeyRecordStructure {
                id,
                public_key,
                private_key,
            },
        }
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        Ok(Self {
            pre_key: PreKeyRecordStructure::decode(data)?,
        })
    }

    pub fn id(&self) -> Result<PreKeyId> {
        Ok(self.pre_key.id)
    }

    pub fn key_pair(&self) -> Result<KeyPair> {
        KeyPair::from_public_and_private(&self.pre_key.public_key, &self.pre_key.private_key)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::deserialize(&self.pre_key.public_key)
    }

    pub fn private_key(&self) -> Result<PrivateKey> {
        PrivateKey::deserialize(&self.pre_key.private_key)
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.pre_key.encode_to_vec())
    }
}
