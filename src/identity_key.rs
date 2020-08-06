use crate::curve;
use crate::proto;

use crate::error::{Result, SignalProtocolError};

use rand::{CryptoRng, Rng};
use std::convert::TryFrom;

use prost::Message;

#[derive(Debug, PartialOrd, Clone, Copy)]
pub struct IdentityKey {
    public_key: curve::PublicKey,
}

impl IdentityKey {
    pub fn new(public_key: curve::PublicKey) -> Self {
        Self { public_key }
    }

    #[inline]
    pub fn public_key(&self) -> &curve::PublicKey {
        &self.public_key
    }

    #[inline]
    pub fn serialize(&self) -> Box<[u8]> {
        self.public_key.serialize()
    }

    pub fn decode(value: &[u8]) -> Result<Self> {
        let pk = curve::PublicKey::deserialize(value)?;
        Ok(Self { public_key: pk })
    }
}

impl TryFrom<&[u8]> for IdentityKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        IdentityKey::decode(value)
    }
}

impl From<curve::PublicKey> for IdentityKey {
    fn from(value: curve::PublicKey) -> Self {
        Self { public_key: value }
    }
}

impl Eq for IdentityKey {}

impl PartialEq for IdentityKey {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl Ord for IdentityKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.public_key.cmp(&other.public_key)
    }
}

#[derive(Copy, Clone)]
pub struct IdentityKeyPair {
    identity_key: IdentityKey,
    private_key: curve::PrivateKey,
}

impl IdentityKeyPair {
    pub fn new(identity_key: IdentityKey, private_key: curve::PrivateKey) -> Self {
        Self {
            identity_key,
            private_key,
        }
    }

    pub fn generate<R: CryptoRng + Rng>(csprng: &mut R) -> Self {
        let keypair = curve::KeyPair::generate(csprng);

        Self {
            identity_key: keypair.public_key.into(),
            private_key: keypair.private_key,
        }
    }

    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    #[inline]
    pub fn public_key(&self) -> &curve::PublicKey {
        &self.identity_key.public_key()
    }

    #[inline]
    pub fn private_key(&self) -> &curve::PrivateKey {
        &self.private_key
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let structure = proto::storage::IdentityKeyPairStructure {
            public_key: self.identity_key.serialize().to_vec(),
            private_key: self.private_key.serialize().to_vec(),
        };
        let mut result = Vec::new();
        structure.encode(&mut result).unwrap();
        result.into_boxed_slice()
    }
}

impl TryFrom<&[u8]> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let structure = proto::storage::IdentityKeyPairStructure::decode(value)?;
        Ok(Self {
            identity_key: IdentityKey::try_from(&structure.public_key[..])?,
            private_key: curve::PrivateKey::deserialize(&structure.private_key)?,
        })
    }
}

impl From<curve::KeyPair> for IdentityKeyPair {
    fn from(value: curve::KeyPair) -> Self {
        Self {
            identity_key: value.public_key.into(),
            private_key: value.private_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::OsRng;

    #[test]
    fn test_identity_key_from() {
        let key_pair = curve::KeyPair::generate(&mut OsRng);
        let key_pair_public_serialized = key_pair.public_key.serialize();
        let identity_key = IdentityKey::from(key_pair.public_key);
        assert_eq!(key_pair_public_serialized, identity_key.serialize());
    }

    #[test]
    fn test_serialize_identity_key_pair() {
        let identity_key_pair = IdentityKeyPair::generate(&mut OsRng);
        let serialized = identity_key_pair.serialize();
        let deserialized_identity_key_pair = IdentityKeyPair::try_from(&serialized[..]).unwrap();
        assert_eq!(
            identity_key_pair.identity_key(),
            deserialized_identity_key_pair.identity_key()
        );
        assert_eq!(
            identity_key_pair.private_key().key_type(),
            deserialized_identity_key_pair.private_key().key_type()
        );
        assert_eq!(
            identity_key_pair.private_key().serialize(),
            deserialized_identity_key_pair.private_key().serialize()
        );
    }
}
