use crate::curve::KeyType;

use std::error::Error;
use std::fmt;

pub type Result<T> = std::result::Result<T, SignalProtocolError>;

#[derive(Debug, Clone)]
pub enum SignalProtocolError {
    InvalidArgument(String),
    InvalidState(&'static str, String),

    ProtobufDecodingError(prost::DecodeError),
    ProtobufEncodingError(prost::EncodeError),
    InvalidProtobufEncoding,

    CiphertextMessageTooShort(usize),
    LegacyCiphertextVersion(u8),
    UnrecognizedCiphertextVersion(u8),
    UnrecognizedMessageVersion(u32),

    FingerprintIdentifierMismatch,
    FingerprintVersionMismatch,

    NoKeyTypeIdentifier,
    BadKeyType(u8),
    BadKeyLength(KeyType, usize),
    MismatchedKeyTypes(KeyType, KeyType),
    MismatchedSignatureLengthForKey(KeyType, usize),

    SignatureValidationFailed,

    UntrustedIdentity(crate::ProtocolAddress),

    InvalidPreKeyId,
    InvalidSignedPreKeyId,

    InvalidPreKeyBundle,

    InvalidRootKeyLength(usize),
    InvalidChainKeyLength(usize),

    InvalidCipherKeyLength(usize),
    InvalidMacKeyLength(usize),
    InvalidCipherNonceLength(usize),
}

impl Error for SignalProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SignalProtocolError::ProtobufEncodingError(ref e) => Some(e),
            SignalProtocolError::ProtobufDecodingError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<prost::DecodeError> for SignalProtocolError {
    fn from(value: prost::DecodeError) -> SignalProtocolError {
        SignalProtocolError::ProtobufDecodingError(value)
    }
}

impl From<prost::EncodeError> for SignalProtocolError {
    fn from(value: prost::EncodeError) -> SignalProtocolError {
        SignalProtocolError::ProtobufEncodingError(value)
    }
}

impl fmt::Display for SignalProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        match self {
            SignalProtocolError::ProtobufDecodingError(ref e) => {
                write!(f, "failed to decode protobuf: {}", e)
            }
            SignalProtocolError::ProtobufEncodingError(ref e) => {
                write!(f, "failed to encode protobuf: {}", e)
            }
            SignalProtocolError::InvalidProtobufEncoding => {
                write!(f, "protobuf encoding was invalid")
            }
            SignalProtocolError::InvalidArgument(ref s) => {
                write!(f, "invalid argument: {}", s)
            }
            SignalProtocolError::InvalidState(ref func, ref s) => {
                write!(f, "invalid state for call to {} to succeed: {}", func, s)
            }
            SignalProtocolError::CiphertextMessageTooShort(size) => {
                write!(f, "ciphertext serialized bytes were too short <{}>", size)
            }
            SignalProtocolError::LegacyCiphertextVersion(version) => {
                write!(f, "ciphertext version was too old <{}>", version)
            }
            SignalProtocolError::UnrecognizedCiphertextVersion(version) => {
                write!(f, "ciphertext version was unrecognized <{}>", version)
            }
            SignalProtocolError::UnrecognizedMessageVersion(message_version) => {
                write!(f, "unrecognized message version <{}>", message_version)
            }
            SignalProtocolError::FingerprintIdentifierMismatch => {
                write!(f, "fingerprint identifiers do not match")
            }
            SignalProtocolError::FingerprintVersionMismatch => {
                write!(f, "fingerprint version numbers do not match")
            }
            SignalProtocolError::NoKeyTypeIdentifier => {
                write!(f, "no key type identifier")
            }
            SignalProtocolError::BadKeyType(t) => {
                write!(f, "bad key type <{:#04x}>", t)
            }
            SignalProtocolError::BadKeyLength(t, l) => {
                write!(f, "bad key length <{}> for key with type <{}>", l, t)
            }
            SignalProtocolError::MismatchedKeyTypes(a, b) => {
                write!(f, "key types <{}> and <{}> do not match", a, b)
            }
            SignalProtocolError::MismatchedSignatureLengthForKey(t, l) => {
                write!(f, "signature length <{}> does not match expected for key with type <{}>", l, t)
            }
            SignalProtocolError::InvalidPreKeyId => {
                write!(f, "invalid prekey identifier")
            }
            SignalProtocolError::InvalidSignedPreKeyId => {
                write!(f, "invalid signed prekey identifier")
            }
            SignalProtocolError::InvalidChainKeyLength(l) => {
                write!(f, "invalid chain key length <{}>", l)
            }
            SignalProtocolError::InvalidRootKeyLength(l) => {
                write!(f, "invalid root key length <{}>", l)
            }
            SignalProtocolError::InvalidCipherKeyLength(l) => {
                write!(f, "invalid cipher key length <{}>", l)
            }
            SignalProtocolError::InvalidMacKeyLength(l) => {
                write!(f, "invalid MAC key length <{}>", l)
            }
            SignalProtocolError::InvalidCipherNonceLength(l) => {
                write!(f, "invalid cipher nonce length <{}>", l)
            }
            SignalProtocolError::UntrustedIdentity(addr) => {
                write!(f, "untrusted identity for address {}", addr)
            }
            SignalProtocolError::SignatureValidationFailed => {
                write!(f, "invalid signature detected")
            }
            SignalProtocolError::InvalidPreKeyBundle => {
                write!(f, "invalid pre key bundle format")
            }
        }
    }
}
