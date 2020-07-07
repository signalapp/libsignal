use crate::curve;
use crate::proto;

use crate::error::{SignalProtocolError, Result};

use std::convert::TryFrom;
use rand::{Rng, CryptoRng};

use prost::Message;

#[derive(Debug, PartialOrd)]
pub struct IdentityKey {
    public_key: Box<dyn curve::PublicKey>,
}

impl IdentityKey {
    #[inline]
    pub fn public_key(&self) -> &(dyn curve::PublicKey + 'static) {
        self.public_key.as_ref()
    }

    #[inline]
    pub fn serialize(&self) -> Box<[u8]> {
        self.public_key.serialize()
    }

    pub fn decode(value: &[u8]) -> Result<Self> {
        let pt = curve::decode_point(value)?;
        Ok(Self { public_key: pt })
    }
}

impl TryFrom<&[u8]> for IdentityKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        IdentityKey::decode(value).into()
    }
}

impl Clone for IdentityKey {
    fn clone(&self) -> Self {
        IdentityKey {
            public_key: curve::decode_point(&self.public_key.serialize()[..]).expect("Serialization round trips properly"),
        }
    }
}

impl<T> From<T> for IdentityKey
where
    T: curve::PublicKey + 'static,
{
    fn from(value: T) -> Self {
        Self {
            public_key: Box::new(value),
        }
    }
}

impl From<Box<dyn curve::PublicKey>> for IdentityKey {
    fn from(value: Box<dyn curve::PublicKey>) -> Self {
        Self { public_key: value }
    }
}

impl Eq for IdentityKey {}

impl PartialEq for IdentityKey {
    fn eq(&self, other: &Self) -> bool {
        self.public_key.as_ref() == other.public_key.as_ref()
    }
}

impl Ord for IdentityKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.public_key.as_ref().cmp(other.public_key.as_ref())
    }
}

pub struct IdentityKeyPair {
    identity_key: IdentityKey,
    private_key: Box<dyn curve::PrivateKey>,
}

impl Clone for IdentityKeyPair {
    fn clone(&self) -> Self {
        IdentityKeyPair {
            identity_key: self.identity_key.clone(),
            private_key: curve::decode_private_point(&self.private_key.serialize()).expect("Serializion round trips"),
        }
    }
}

impl IdentityKeyPair {
    pub fn new(identity_key: IdentityKey, private_key: Box<dyn curve::PrivateKey>) -> Self {
        Self {
            identity_key,
            private_key,
        }
    }

    pub fn generate<R: CryptoRng + Rng>(csprng: &mut R) -> Self {
        curve::KeyPair::new(csprng).into()
    }


    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    #[inline]
    pub fn private_key(&self) -> &dyn curve::PrivateKey {
        self.private_key.as_ref()
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let structure = proto::storage::IdentityKeyPairStructure {
            public_key: self.identity_key.serialize().into_vec(),
            private_key: self.private_key.serialize().into_vec(),
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
            private_key: curve::decode_private_point(&structure.private_key[..])?,
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
        let key_pair = curve::KeyPair::new(&mut OsRng);
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
