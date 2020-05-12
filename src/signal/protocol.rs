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
use rand::{CryptoRng, Rng};

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
    SignalMessage(SignalMessage),
    PreKeySignalMessage(PreKeySignalMessage),
    SenderKeyMessage(SenderKeyMessage),
    SenderKeyDistributionMessage(SenderKeyDistributionMessage),
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
    pub fn sender_ratchet_key(&self) -> &(dyn curve::PublicKey + 'static) {
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

impl TryFrom<&[u8]> for SignalMessage {
    type Error = CiphertextMessageDeserializationError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < SignalMessage::MAC_LENGTH + 1 {
            return Err(CiphertextMessageDeserializationError::MessageTooShort(
                value.len(),
            ));
        }
        let message_version = value[0] >> 4;
        let ciphertext_version = value[0] & 0x0F;
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
            proto::wire::SignalMessage::decode(&value[1..value.len() - SignalMessage::MAC_LENGTH])?;
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
            serialized: Box::from(value),
        })
    }
}

pub struct PreKeySignalMessage {
    message_version: u8,
    registration_id: u32,
    pre_key_id: Option<u32>,
    signed_pre_key_id: u32,
    base_key: Box<dyn curve::PublicKey>,
    identity_key: IdentityKey,
    message: SignalMessage,
    serialized: Box<[u8]>,
}

impl PreKeySignalMessage {
    pub fn new(
        message_version: u8,
        registration_id: u32,
        pre_key_id: Option<u32>,
        signed_pre_key_id: u32,
        base_key: Box<dyn curve::PublicKey>,
        identity_key: IdentityKey,
        message: SignalMessage,
    ) -> Self {
        let proto_message = proto::wire::PreKeySignalMessage {
            registration_id: Some(registration_id),
            pre_key_id,
            signed_pre_key_id: Some(signed_pre_key_id),
            base_key: Some(base_key.serialize().into_vec()),
            identity_key: Some(identity_key.serialize().into_vec()),
            message: Some(Vec::from(message.as_ref())),
        };
        let mut serialized = vec![0u8; 1 + proto_message.encoded_len()];
        serialized[0] = ((message_version & 0xF) << 4) | CIPHERTEXT_MESSAGE_CURRENT_VERSION;
        proto_message.encode(&mut &mut serialized[1..]).unwrap();
        Self {
            message_version,
            registration_id,
            pre_key_id,
            signed_pre_key_id,
            base_key,
            identity_key,
            message,
            serialized: serialized.into_boxed_slice(),
        }
    }

    #[inline]
    pub fn message_version(&self) -> u8 {
        self.message_version
    }

    #[inline]
    pub fn registration_id(&self) -> u32 {
        self.registration_id
    }

    #[inline]
    pub fn pre_key_id(&self) -> Option<u32> {
        self.pre_key_id
    }

    #[inline]
    pub fn signed_pre_key_id(&self) -> u32 {
        self.signed_pre_key_id
    }

    #[inline]
    pub fn base_key(&self) -> &(dyn curve::PublicKey + 'static) {
        &*self.base_key
    }

    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    #[inline]
    pub fn message(&self) -> &SignalMessage {
        &self.message
    }
}

impl AsRef<[u8]> for PreKeySignalMessage {
    fn as_ref(&self) -> &[u8] {
        &*self.serialized
    }
}

impl TryFrom<&[u8]> for PreKeySignalMessage {
    type Error = CiphertextMessageDeserializationError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(CiphertextMessageDeserializationError::MessageTooShort(
                value.len(),
            ));
        }

        let message_version = value[0] >> 4;
        let ciphertext_version = value[0] & 0x0F;
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

        let proto_structure = proto::wire::PreKeySignalMessage::decode(&value[1..])?;
        if proto_structure.signed_pre_key_id.is_none()
            || proto_structure.base_key.is_none()
            || proto_structure.identity_key.is_none()
            || proto_structure.message.is_none()
        {
            return Err(CiphertextMessageDeserializationError::InvalidMessage(None));
        }
        let base_key = curve::decode_point(proto_structure.base_key.unwrap().as_ref())?;
        Ok(PreKeySignalMessage {
            message_version,
            registration_id: proto_structure.registration_id.unwrap_or(0),
            pre_key_id: proto_structure.pre_key_id,
            signed_pre_key_id: proto_structure.signed_pre_key_id.unwrap(),
            base_key,
            identity_key: IdentityKey::try_from(proto_structure.identity_key.unwrap().as_ref())?,
            message: SignalMessage::try_from(proto_structure.message.unwrap().as_ref())?,
            serialized: Box::from(value),
        })
    }
}

pub struct SenderKeyMessage {
    message_version: u8,
    key_id: u32,
    iteration: u32,
    ciphertext: Box<[u8]>,
    serialized: Box<[u8]>,
}

impl SenderKeyMessage {
    const SIGNATURE_LEN: usize = 64;

    pub fn new<R>(
        key_id: u32,
        iteration: u32,
        ciphertext: Box<[u8]>,
        csprng: &mut R,
        signature_key: &dyn curve::PrivateKey,
    ) -> Self
    where
        R: CryptoRng + Rng,
    {
        let proto_message = proto::wire::SenderKeyMessage {
            id: Some(key_id),
            iteration: Some(iteration),
            ciphertext: Some(ciphertext.clone().into_vec()),
        };
        let proto_message_len = proto_message.encoded_len();
        let mut serialized = vec![0u8; 1 + proto_message_len + Self::SIGNATURE_LEN];
        serialized[0] =
            ((CIPHERTEXT_MESSAGE_CURRENT_VERSION & 0xF) << 4) | CIPHERTEXT_MESSAGE_CURRENT_VERSION;
        proto_message
            .encode(&mut &mut serialized[1..1 + proto_message_len])
            .unwrap();
        let signature =
            curve::calculate_signature(csprng, signature_key, &serialized[..1 + proto_message_len]);
        serialized[1 + proto_message_len..].copy_from_slice(&signature[..]);
        Self {
            message_version: CIPHERTEXT_MESSAGE_CURRENT_VERSION,
            key_id,
            iteration,
            ciphertext,
            serialized: serialized.into_boxed_slice(),
        }
    }

    pub fn verify_signature(&self, signature_key: &dyn curve::PublicKey) -> bool {
        curve::verify_signature(
            signature_key,
            &self.serialized[..self.serialized.len() - Self::SIGNATURE_LEN],
            &self.serialized[self.serialized.len() - Self::SIGNATURE_LEN..],
        )
        .unwrap()
    }

    #[inline]
    pub fn message_version(&self) -> u8 {
        self.message_version
    }

    #[inline]
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    #[inline]
    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    #[inline]
    pub fn ciphertext(&self) -> &[u8] {
        &*self.ciphertext
    }
}

impl AsRef<[u8]> for SenderKeyMessage {
    fn as_ref(&self) -> &[u8] {
        &*self.serialized
    }
}

impl TryFrom<&[u8]> for SenderKeyMessage {
    type Error = CiphertextMessageDeserializationError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 1 + Self::SIGNATURE_LEN {
            return Err(CiphertextMessageDeserializationError::MessageTooShort(
                value.len(),
            ));
        }
        let message_version = value[0] >> 4;
        let ciphertext_version = value[0] & 0x0F;
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
            proto::wire::SenderKeyMessage::decode(&value[1..value.len() - Self::SIGNATURE_LEN])?;
        if proto_structure.id.is_none()
            || proto_structure.iteration.is_none()
            || proto_structure.ciphertext.is_none()
        {
            return Err(CiphertextMessageDeserializationError::InvalidMessage(None));
        }
        Ok(SenderKeyMessage {
            message_version,
            key_id: proto_structure.id.unwrap(),
            iteration: proto_structure.iteration.unwrap(),
            ciphertext: proto_structure.ciphertext.unwrap().into_boxed_slice(),
            serialized: Box::from(value),
        })
    }
}

pub struct SenderKeyDistributionMessage {}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::OsRng;
    use rand::{CryptoRng, Rng, RngCore};

    fn create_signal_message<T>(csprng: &mut T) -> SignalMessage
    where
        T: Rng + CryptoRng,
    {
        let mut mac_key = [0u8; 32];
        csprng.fill_bytes(&mut mac_key);
        let mac_key = mac_key;

        let mut ciphertext = [0u8; 20];
        csprng.fill_bytes(&mut ciphertext);
        let ciphertext = ciphertext;

        let sender_ratchet_key_pair = curve::KeyPair::new(csprng);
        let sender_identity_key_pair = curve::KeyPair::new(csprng);
        let receiver_identity_key_pair = curve::KeyPair::new(csprng);

        SignalMessage::new(
            3,
            &mac_key,
            sender_ratchet_key_pair.public_key,
            42,
            41,
            Box::new(ciphertext),
            &sender_identity_key_pair.public_key.into(),
            &receiver_identity_key_pair.public_key.into(),
        )
    }

    fn assert_signal_message_equals(m1: &SignalMessage, m2: &SignalMessage) {
        assert_eq!(m1.message_version, m2.message_version);
        assert_eq!(*m1.sender_ratchet_key, *m2.sender_ratchet_key);
        assert_eq!(m1.counter, m2.counter);
        assert_eq!(m1.previous_counter, m2.previous_counter);
        assert_eq!(m1.ciphertext, m2.ciphertext);
        assert_eq!(m1.serialized, m2.serialized);
    }

    #[test]
    fn test_signal_message_serialize_deserialize() {
        let mut csprng = OsRng;
        let message = create_signal_message(&mut csprng);
        let deser_message =
            SignalMessage::try_from(message.as_ref()).expect("should deserialize without error");
        assert_signal_message_equals(&message, &deser_message);
    }

    #[test]
    fn test_pre_key_signal_message_serialize_deserialize() {
        let mut csprng = OsRng;
        let identity_key_pair = curve::KeyPair::new(&mut csprng);
        let base_key_pair = curve::KeyPair::new(&mut csprng);
        let message = create_signal_message(&mut csprng);
        let pre_key_signal_message = PreKeySignalMessage::new(
            3,
            365,
            None,
            97,
            base_key_pair.public_key,
            identity_key_pair.public_key.into(),
            message,
        );
        let deser_pre_key_signal_message =
            PreKeySignalMessage::try_from(pre_key_signal_message.as_ref())
                .expect("should deserialized without error");
        assert_eq!(
            pre_key_signal_message.message_version,
            deser_pre_key_signal_message.message_version
        );
        assert_eq!(
            pre_key_signal_message.registration_id,
            deser_pre_key_signal_message.registration_id
        );
        assert_eq!(
            pre_key_signal_message.pre_key_id,
            deser_pre_key_signal_message.pre_key_id
        );
        assert_eq!(
            pre_key_signal_message.signed_pre_key_id,
            deser_pre_key_signal_message.signed_pre_key_id
        );
        assert_eq!(
            *pre_key_signal_message.base_key,
            *deser_pre_key_signal_message.base_key
        );
        assert_eq!(
            pre_key_signal_message.identity_key.public_key(),
            deser_pre_key_signal_message.identity_key.public_key()
        );
        assert_signal_message_equals(
            &pre_key_signal_message.message,
            &deser_pre_key_signal_message.message,
        );
        assert_eq!(
            pre_key_signal_message.serialized,
            deser_pre_key_signal_message.serialized
        );
    }
}
