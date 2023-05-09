//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::curve::KeyType;
use crate::kem;

use displaydoc::Display;
use thiserror::Error;
use uuid::Uuid;

use std::panic::UnwindSafe;

pub type Result<T> = std::result::Result<T, SignalProtocolError>;

#[derive(Debug, Display, Error)]
pub enum SignalProtocolError {
    /// invalid argument: {0}
    InvalidArgument(String),
    /// invalid state for call to {0} to succeed: {1}
    InvalidState(&'static str, String),

    /// protobuf encoding was invalid
    InvalidProtobufEncoding,

    /// ciphertext serialized bytes were too short <{0}>
    CiphertextMessageTooShort(usize),
    /// ciphertext version was too old <{0}>
    LegacyCiphertextVersion(u8),
    /// ciphertext version was unrecognized <{0}>
    UnrecognizedCiphertextVersion(u8),
    /// unrecognized message version <{0}>
    UnrecognizedMessageVersion(u32),

    /// fingerprint version number mismatch them {0} us {1}
    FingerprintVersionMismatch(u32, u32),
    /// fingerprint parsing error
    FingerprintParsingError,

    /// no key type identifier
    NoKeyTypeIdentifier,
    /// bad key type <{0:#04x}>
    BadKeyType(u8),
    /// bad key length <{1}> for key with type <{0}>
    BadKeyLength(KeyType, usize),

    /// invalid signature detected
    SignatureValidationFailed,

    /// untrusted identity for address {0}
    UntrustedIdentity(crate::ProtocolAddress),

    /// invalid prekey identifier
    InvalidPreKeyId,
    /// invalid signed prekey identifier
    InvalidSignedPreKeyId,
    /// invalid Kyber prekey identifier
    InvalidKyberPreKeyId,

    /// invalid MAC key length <{0}>
    InvalidMacKeyLength(usize),

    /// missing sender key state for distribution ID {distribution_id}
    NoSenderKeyState { distribution_id: Uuid },

    /// session with {0} not found
    SessionNotFound(crate::ProtocolAddress),
    /// invalid session: {0}
    InvalidSessionStructure(&'static str),
    /// invalid sender key session with distribution ID {distribution_id}
    InvalidSenderKeySession { distribution_id: Uuid },
    /// session for {0} has invalid registration ID {1:X}
    InvalidRegistrationId(crate::ProtocolAddress, u32),

    /// message with old counter {0} / {1}
    DuplicatedMessage(u32, u32),
    /// invalid {0:?} message: {1}
    InvalidMessage(crate::CiphertextMessageType, &'static str),

    /// error while invoking an ffi callback: {0}
    FfiBindingError(String),
    /// error in method call '{0}': {1}
    ApplicationCallbackError(
        &'static str,
        #[source] Box<dyn std::error::Error + Send + Sync + UnwindSafe + 'static>,
    ),

    /// invalid sealed sender message: {0}
    InvalidSealedSenderMessage(String),
    /// unknown sealed sender message version {0}
    UnknownSealedSenderVersion(u8),
    /// self send of a sealed sender message
    SealedSenderSelfSend,

    /// bad KEM key type <{0:#04x}>
    BadKEMKeyType(u8),
    /// unexpected KEM key type <{0:#04x}> (expected <{1:#04x}>)
    WrongKEMKeyType(u8, u8),
    /// bad KEM key length <{1}> for key with type <{0}>
    BadKEMKeyLength(kem::KeyType, usize),
    /// bad KEM ciphertext length <{1}> for key with type <{0}>
    BadKEMCiphertextLength(kem::KeyType, usize),
}
