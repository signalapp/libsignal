use std::fmt;

use rand::TryRngCore as _;

use crate::proto::storage::SignedPreKeyRecordStructure;
use crate::state::{GenericSignedPreKey, signed_prekey::{KeySerde, KeyPairSerde}};
use crate::{PrivateKey, Result, Timestamp};
use pswoosh::keys::{SwooshKeyPair, PrivateSwooshKey, PublicSwooshKey};

/// A unique identifier selecting among this client's known signed pre-keys.
#[derive(
    Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, derive_more::From, derive_more::Into,
)]
pub struct SwooshPreKeyId(u32);

impl fmt::Display for SwooshPreKeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct SwooshPreKeyRecord {
    signed_pre_key: SignedPreKeyRecordStructure,
}

impl GenericSignedPreKey for SwooshPreKeyRecord {
    type KeyPair = SwooshKeyPair;
    type Id = SwooshPreKeyId;

    fn get_storage(&self) -> &SignedPreKeyRecordStructure {
        &self.signed_pre_key
    }

    fn from_storage(storage: SignedPreKeyRecordStructure) -> Self {
        Self {
            signed_pre_key: storage,
        }
    }
}

impl SwooshPreKeyRecord {
    pub fn secret_key(&self) -> Result<pswoosh::keys::PrivateSwooshKey> {
        Ok(PrivateSwooshKey::deserialize(&self.signed_pre_key.private_key)?)
    }
}

impl SwooshPreKeyRecord {
    pub fn generate(
        id: SwooshPreKeyId,
        signing_key: &PrivateKey,
    ) -> Result<SwooshPreKeyRecord> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let key_pair = SwooshKeyPair::generate(true);
        let signature = signing_key
            .calculate_signature(&key_pair.public_key.serialize(), &mut rng)?
            .into_vec();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("Time should move forward")
            .as_millis();
        Ok(SwooshPreKeyRecord::new(
            id,
            Timestamp::from_epoch_millis(timestamp.try_into().expect("Timestamp too large")),
            &key_pair,
            &signature,
        ))
    }
}

impl KeySerde for PublicSwooshKey {
    fn serialize(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }

    fn deserialize<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        Ok(Self::deserialize(bytes.as_ref())?)
    }
}

impl KeySerde for PrivateSwooshKey {
    fn serialize(&self) -> Vec<u8> {
        self.serialize()
    }

    fn deserialize<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        Ok(Self::deserialize(bytes.as_ref())?)
    }
}

impl KeyPairSerde for SwooshKeyPair {
    type PublicKey = PublicSwooshKey;
    type PrivateKey = PrivateSwooshKey;

    fn from_public_and_private(public_key: &[u8], private_key: &[u8]) -> Result<Self> {
        Ok(SwooshKeyPair::from_public_and_private(public_key, private_key)?)
    }

    fn get_public(&self) -> &PublicSwooshKey {
        &self.public_key
    }

    fn get_private(&self) -> &PrivateSwooshKey {
        &self.private_key
    }
}