use std::convert::TryFrom;

pub mod curve;
mod error;
pub mod kdf;
pub(crate) mod proto;

pub mod ratchet;
pub use error::Error;

pub struct IdentityKey {
    public_key: Box<dyn curve::PublicKey>,
}

impl IdentityKey {
    pub fn public_key(&self) -> &dyn curve::PublicKey {
        self.public_key.as_ref()
    }

    pub fn serialize(&self) -> Box<[u8]> {
        self.public_key.serialize()
    }
}

impl TryFrom<&[u8]> for IdentityKey {
    type Error = curve::InvalidKeyError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        curve::decode_point(value).map(|public_key| Self { public_key })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from() {
        use rand::rngs::OsRng;

        let key_pair = curve::KeyPair::new(&mut OsRng);
        let key_pair_public_serialized = key_pair.public_key.serialize();
        let identity_key = IdentityKey::from(key_pair.public_key);
        assert_eq!(key_pair_public_serialized, identity_key.serialize());
    }
}
