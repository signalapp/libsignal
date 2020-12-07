//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::curve::KeyType;

use std::error::Error;
use std::fmt;

pub type Result<T> = std::result::Result<T, SignalProtocolError>;

#[derive(Debug)]
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
    SignaturePubkeyMissing,

    UntrustedIdentity(crate::ProtocolAddress),

    InvalidPreKeyId,
    InvalidSignedPreKeyId,
    InvalidSenderKeyId,

    InvalidPreKeyBundle,

    InvalidRootKeyLength(usize),
    InvalidChainKeyLength(usize),

    InvalidMacKeyLength(usize),
    InvalidCipherCryptographicParameters(usize, usize),
    InvalidCiphertext,

    NoSenderKeyState,
    SenderKeySigningKeyMissing,

    SessionNotFound,
    InvalidSessionStructure,

    DuplicatedMessage(u32, u32),
    InvalidMessage(&'static str),
    InternalError(&'static str),
    FfiBindingError(String),
    ApplicationCallbackError(&'static str, Box<dyn Error + 'static>),

    InvalidSealedSenderMessage(String),
    UnknownSealedSenderVersion(u8),
    SealedSenderSelfSend,
}

impl Error for SignalProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SignalProtocolError::ProtobufEncodingError(e) => Some(e),
            SignalProtocolError::ProtobufDecodingError(e) => Some(e),
            SignalProtocolError::ApplicationCallbackError(_, e) => Some(e.as_ref()),
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
            SignalProtocolError::ProtobufDecodingError(e) => {
                write!(f, "failed to decode protobuf: {}", e)
            }
            SignalProtocolError::ProtobufEncodingError(e) => {
                write!(f, "failed to encode protobuf: {}", e)
            }
            SignalProtocolError::InvalidProtobufEncoding => {
                write!(f, "protobuf encoding was invalid")
            }
            SignalProtocolError::InvalidArgument(s) => write!(f, "invalid argument: {}", s),
            SignalProtocolError::InvalidState(func, s) => {
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
            SignalProtocolError::NoKeyTypeIdentifier => write!(f, "no key type identifier"),
            SignalProtocolError::BadKeyType(t) => write!(f, "bad key type <{:#04x}>", t),
            SignalProtocolError::BadKeyLength(t, l) => {
                write!(f, "bad key length <{}> for key with type <{}>", l, t)
            }
            SignalProtocolError::MismatchedKeyTypes(a, b) => {
                write!(f, "key types <{}> and <{}> do not match", a, b)
            }
            SignalProtocolError::MismatchedSignatureLengthForKey(t, l) => write!(
                f,
                "signature length <{}> does not match expected for key with type <{}>",
                l, t
            ),
            SignalProtocolError::InvalidPreKeyId => write!(f, "invalid prekey identifier"),
            SignalProtocolError::InvalidSignedPreKeyId => {
                write!(f, "invalid signed prekey identifier")
            }
            SignalProtocolError::InvalidChainKeyLength(l) => {
                write!(f, "invalid chain key length <{}>", l)
            }
            SignalProtocolError::InvalidRootKeyLength(l) => {
                write!(f, "invalid root key length <{}>", l)
            }
            SignalProtocolError::InvalidCipherCryptographicParameters(kl, nl) => write!(
                f,
                "invalid cipher key length <{}> or nonce length <{}>",
                kl, nl
            ),
            SignalProtocolError::InvalidMacKeyLength(l) => {
                write!(f, "invalid MAC key length <{}>", l)
            }
            SignalProtocolError::UntrustedIdentity(addr) => {
                write!(f, "untrusted identity for address {}", addr)
            }
            SignalProtocolError::SignatureValidationFailed => {
                write!(f, "invalid signature detected")
            }
            SignalProtocolError::InvalidPreKeyBundle => write!(f, "invalid pre key bundle format"),
            SignalProtocolError::InvalidCiphertext => write!(f, "invalid ciphertext message"),
            SignalProtocolError::SessionNotFound => write!(f, "session not found"),
            SignalProtocolError::InvalidSessionStructure => write!(f, "invalid session structure"),
            SignalProtocolError::DuplicatedMessage(i, c) => {
                write!(f, "message with old counter {} / {}", i, c)
            }
            SignalProtocolError::InvalidMessage(m) => write!(f, "invalid message {}", m),
            SignalProtocolError::InternalError(m) => write!(f, "internal error {}", m),
            SignalProtocolError::InvalidSenderKeyId => write!(f, "invalid send key id"),
            SignalProtocolError::NoSenderKeyState => write!(f, "no sender key state"),
            SignalProtocolError::SenderKeySigningKeyMissing => {
                write!(f, "sender key signature key missing")
            }
            SignalProtocolError::SignaturePubkeyMissing => {
                write!(f, "cannot verify signature due to missing key")
            }
            SignalProtocolError::FfiBindingError(m) => {
                write!(f, "error while invoking an ffi callback: {}", m)
            }
            SignalProtocolError::ApplicationCallbackError(func, c) => {
                write!(f, "application callback {} failed with {}", func, c)
            }
            SignalProtocolError::InvalidSealedSenderMessage(m) => {
                write!(f, "invalid sealed sender message {}", m)
            }
            SignalProtocolError::UnknownSealedSenderVersion(v) => {
                write!(f, "unknown sealed sender message version {}", v)
            }
            SignalProtocolError::SealedSenderSelfSend => {
                write!(f, "self send of a sealed sender message")
            }
        }
    }
}
