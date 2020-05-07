use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use hmac::{Hmac, Mac};
use prost::{DecodeError, Message};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::curve;
use super::proto;
use crate::signal::IdentityKey;

pub const CIPHERTEXT_MESSAGE_CURRENT_VERSION: u8 = 3;

#[derive(Debug)]
pub enum CiphertextMessageDeserializationError {
    MessageTooShort(usize),
    LegacyVersion(u8),
    UnrecognizedVersion(u8),
    InvalidMessage(Option<Box<dyn Error>>),
}

impl Display for CiphertextMessageDeserializationError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            CiphertextMessageDeserializationError::MessageTooShort(size) => {
                write!(f, "ciphertext serialized bytes were too short <{}>", size)
            }
            CiphertextMessageDeserializationError::LegacyVersion(version) => {
                write!(f, "ciphertext version was too old <{}>", version)
            }
            CiphertextMessageDeserializationError::UnrecognizedVersion(version) => {
                write!(f, "ciphertext version was unrecognized <{}>", version)
            }
            CiphertextMessageDeserializationError::InvalidMessage(source) => match source {
                None => write!(f, "ciphertext was invalid"),
                Some(err) => write!(f, "ciphertext was invalid; caused by: {}", err),
            },
        }
    }
}

impl Error for CiphertextMessageDeserializationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CiphertextMessageDeserializationError::MessageTooShort(_) => None,
            CiphertextMessageDeserializationError::LegacyVersion(_) => None,
            CiphertextMessageDeserializationError::UnrecognizedVersion(_) => None,
            CiphertextMessageDeserializationError::InvalidMessage(source) => match source {
                None => None,
                Some(b) => Some(b.as_ref()),
            },
        }
    }
}

impl From<DecodeError> for CiphertextMessageDeserializationError {
    fn from(value: DecodeError) -> Self {
        CiphertextMessageDeserializationError::InvalidMessage(Some(Box::new(value)))
    }
}

impl From<curve::InvalidKeyError> for CiphertextMessageDeserializationError {
    fn from(value: curve::InvalidKeyError) -> Self {
        CiphertextMessageDeserializationError::InvalidMessage(Some(Box::new(value)))
    }
}

pub enum CiphertextMessage {
    Signal(SignalMessage),
    PreKeySignal(PreKeySignalMessage),
    SenderKey(SenderKeyMessage),
    SenderKeyDistribution(SenderKeyDistributionMessage),
}

pub struct SignalMessage {
    message_version: u8,
    sender_ratchet_key: Box<dyn curve::PublicKey>,
    counter: u32,
    previous_counter: u32,
    ciphertext: Box<[u8]>,
    serialized: Box<[u8]>,
}

impl SignalMessage {
    const MAC_LENGTH: usize = 8;

    pub fn new(
        message_version: u8,
        mac_key: &[u8; 32],
        sender_ratchet_key: Box<dyn curve::PublicKey>,
        counter: u32,
        previous_counter: u32,
        ciphertext: Box<[u8]>,
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
    ) -> Self {
        let message = proto::wire::SignalMessage {
            ratchet_key: Some(sender_ratchet_key.serialize().into_vec()),
            counter: Some(counter),
            previous_counter: Some(previous_counter),
            ciphertext: Some(Vec::<u8>::from(&ciphertext[..])),
        };
        let mut serialized = vec![0u8; 1 + message.encoded_len() + Self::MAC_LENGTH];
        serialized[0] = ((message_version & 0xF) << 4) | CIPHERTEXT_MESSAGE_CURRENT_VERSION;
        message
            .encode(&mut &mut serialized[1..message.encoded_len() + 1])
            .unwrap();
        let msg_len_for_mac = serialized.len() - Self::MAC_LENGTH;
        let mac = Self::compute_mac(
            sender_identity_key,
            receiver_identity_key,
            mac_key,
            &serialized[..msg_len_for_mac],
        );
        serialized[msg_len_for_mac..].copy_from_slice(&mac);
        let serialized = serialized.into_boxed_slice();
        Self {
            message_version,
            sender_ratchet_key,
            counter,
            previous_counter,
            ciphertext,
            serialized,
        }
    }

    #[inline]
    pub fn message_version(&self) -> u8 {
        self.message_version
    }

    #[inline]
    pub fn sender_ratchet_key(&self) -> &dyn curve::PublicKey {
        &*self.sender_ratchet_key
    }

    #[inline]
    pub fn counter(&self) -> u32 {
        self.counter
    }

    #[inline]
    pub fn body(&self) -> &[u8] {
        &*self.ciphertext
    }

    pub fn verify_mac(
        &self,
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
        mac_key: &[u8; 32],
    ) -> bool {
        let our_mac = &Self::compute_mac(
            sender_identity_key,
            receiver_identity_key,
            mac_key,
            &self.serialized[..self.serialized.len() - Self::MAC_LENGTH],
        );
        let their_mac = &self.serialized[self.serialized.len() - Self::MAC_LENGTH..];
        our_mac.ct_eq(their_mac).into()
    }

    fn compute_mac(
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
        mac_key: &[u8; 32],
        message: &[u8],
    ) -> [u8; Self::MAC_LENGTH] {
        let mut mac = Hmac::<Sha256>::new_varkey(mac_key).unwrap();
        mac.input(sender_identity_key.public_key().serialize().as_ref());
        mac.input(receiver_identity_key.public_key().serialize().as_ref());
        mac.input(message);
        let mut result = [0u8; Self::MAC_LENGTH];
        result.copy_from_slice(&mac.result().code()[..Self::MAC_LENGTH]);
        result
    }
}

impl AsRef<[u8]> for SignalMessage {
    fn as_ref(&self) -> &[u8] {
        &*self.serialized
    }
}

impl TryInto<SignalMessage> for &[u8] {
    type Error = CiphertextMessageDeserializationError;

    fn try_into(self) -> Result<SignalMessage, Self::Error> {
        if self.len() < SignalMessage::MAC_LENGTH + 1 {
            return Err(CiphertextMessageDeserializationError::MessageTooShort(
                self.len(),
            ));
        }
        let message_version = self[0] >> 4;
        let ciphertext_version = self[0] & 0x0F;
        if ciphertext_version < CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(CiphertextMessageDeserializationError::LegacyVersion(
                ciphertext_version,
            ));
        }
        if ciphertext_version > CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(CiphertextMessageDeserializationError::UnrecognizedVersion(
                ciphertext_version,
            ));
        }

        let proto_structure =
            proto::wire::SignalMessage::decode(&self[1..self.len() - SignalMessage::MAC_LENGTH])?;
        if proto_structure.ciphertext.is_none()
            || proto_structure.counter.is_none()
            || proto_structure.ratchet_key.is_none()
        {
            return Err(CiphertextMessageDeserializationError::InvalidMessage(None));
        }
        let sender_ratchet_key =
            curve::decode_point(proto_structure.ratchet_key.unwrap().as_ref())?;
        Ok(SignalMessage {
            message_version,
            sender_ratchet_key,
            counter: proto_structure.counter.unwrap(),
            previous_counter: proto_structure.previous_counter.unwrap_or(0),
            ciphertext: proto_structure.ciphertext.unwrap().into_boxed_slice(),
            serialized: Box::from(self),
        })
    }
}

pub struct PreKeySignalMessage {}
pub struct SenderKeyMessage {}
pub struct SenderKeyDistributionMessage {}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::OsRng;
    use rand::RngCore;

    #[test]
    fn test_signal_message_serialize_deserialize() {
        let mut csprng = OsRng;

        let mut mac_key = [0u8; 32];
        csprng.fill_bytes(&mut mac_key);
        let mac_key = mac_key;

        let mut ciphertext = [0u8; 20];
        csprng.fill_bytes(&mut ciphertext);
        let ciphertext = ciphertext;

        let sender_ratchet_key_pair = curve::KeyPair::new(&mut csprng);
        let sender_identity_key_pair = curve::KeyPair::new(&mut csprng);
        let receiver_identity_key_pair = curve::KeyPair::new(&mut csprng);

        let msg = SignalMessage::new(
            3,
            &mac_key,
            sender_ratchet_key_pair.public_key,
            42,
            41,
            Box::new(ciphertext),
            &sender_identity_key_pair.public_key.into(),
            &receiver_identity_key_pair.public_key.into(),
        );
    }
}
