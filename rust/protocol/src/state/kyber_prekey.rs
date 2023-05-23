//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::proto::storage::SignedPreKeyRecordStructure;

use crate::state::GenericSignedPreKey;
use crate::{kem, PrivateKey, Result};

use std::convert::TryInto;
use std::fmt;

/// A unique identifier selecting among this client's known signed pre-keys.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct KyberPreKeyId(u32);

impl From<u32> for KyberPreKeyId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<KyberPreKeyId> for u32 {
    fn from(value: KyberPreKeyId) -> Self {
        value.0
    }
}

impl fmt::Display for KyberPreKeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct KyberPreKeyRecord {
    signed_pre_key: SignedPreKeyRecordStructure,
}

impl GenericSignedPreKey for KyberPreKeyRecord {
    type KeyPair = kem::KeyPair;
    type Id = KyberPreKeyId;

    fn get_storage(&self) -> &SignedPreKeyRecordStructure {
        &self.signed_pre_key
    }

    fn from_storage(storage: SignedPreKeyRecordStructure) -> Self {
        Self {
            signed_pre_key: storage,
        }
    }
}

impl KyberPreKeyRecord {
    pub fn secret_key(&self) -> Result<kem::SecretKey> {
        kem::SecretKey::deserialize(&self.signed_pre_key.private_key)
    }
}

impl KyberPreKeyRecord {
    pub fn generate(
        kyber_key_type: kem::KeyType,
        id: KyberPreKeyId,
        signing_key: &PrivateKey,
    ) -> Result<KyberPreKeyRecord> {
        let key_pair = kem::KeyPair::generate(kyber_key_type);
        let mut rng = rand::rngs::OsRng;
        let signature = signing_key
            .calculate_signature(&key_pair.public_key.serialize(), &mut rng)?
            .into_vec();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("Time should move forward")
            .as_millis();
        Ok(KyberPreKeyRecord::new(
            id,
            timestamp.try_into().expect("Timestamp too large"),
            &key_pair,
            &signature,
        ))
    }
}
