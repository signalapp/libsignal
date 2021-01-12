//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::curve::KeyType;

pub type Result<T> = std::result::Result<T, SignalProtocolError>;

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum SignalProtocolError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("invalid state for call to {0} to succeed: {1}")]
    InvalidState(&'static str, String),

    #[error("failed to decode protobuf: {0}")]
    ProtobufDecodingError(#[from] prost::DecodeError),
    #[error("failed to encode protobuf: {0}")]
    ProtobufEncodingError(#[from] prost::EncodeError),
    #[error("protobuf encoding was invalid")]
    InvalidProtobufEncoding,

    #[error("ciphertext serialized bytes were too short <{0}>")]
    CiphertextMessageTooShort(usize),
    #[error("ciphertext version was too old <{0}>")]
    LegacyCiphertextVersion(u8),
    #[error("ciphertext version was unrecognized <{0}>")]
    UnrecognizedCiphertextVersion(u8),
    #[error("unrecognized message version <{0}>")]
    UnrecognizedMessageVersion(u32),

    #[error("fingerprint identifiers do not match")]
    FingerprintIdentifierMismatch,
    #[error("fingerprint version numbers do not match")]
    FingerprintVersionMismatch,

    #[error("no key type identifier")]
    NoKeyTypeIdentifier,
    #[error("bad key type <{0:#04x}>")]
    BadKeyType(u8),
    #[error("bad key length <{1}> for key with type <{0}>")]
    BadKeyLength(KeyType, usize),
    #[error("key types <{0}> and <{1}> do not match")]
    MismatchedKeyTypes(KeyType, KeyType),
    #[error("signature length <{1}> does not match expected for key with type <{0}>")]
    MismatchedSignatureLengthForKey(KeyType, usize),

    #[error("invalid signature detected")]
    SignatureValidationFailed,
    #[error("cannot verify signature due to missing key")]
    SignaturePubkeyMissing,

    #[error("untrusted identity for address {0}")]
    UntrustedIdentity(crate::ProtocolAddress),

    #[error("invalid prekey identifier")]
    InvalidPreKeyId,
    #[error("invalid signed prekey identifier")]
    InvalidSignedPreKeyId,
    #[error("invalid send key id")]
    InvalidSenderKeyId,

    #[error("invalid pre key bundle format")]
    InvalidPreKeyBundle,

    #[error("invalid root key length <{0}>")]
    InvalidRootKeyLength(usize),
    #[error("invalid chain key length <{0}>")]
    InvalidChainKeyLength(usize),

    #[error("invalid MAC key length <{0}>")]
    InvalidMacKeyLength(usize),
    #[error("invalid cipher key length <{0}> or nonce length <{1}>")]
    InvalidCipherCryptographicParameters(usize, usize),
    #[error("invalid ciphertext message")]
    InvalidCiphertext,

    #[error("no sender key state")]
    NoSenderKeyState,
    #[error("sender key signature key missing")]
    SenderKeySigningKeyMissing,

    #[error("session not found")]
    SessionNotFound,
    #[error("invalid session structure")]
    InvalidSessionStructure,

    #[error("message with old counter {0} / {1}")]
    DuplicatedMessage(u32, u32),
    #[error("invalid message {0}")]
    InvalidMessage(&'static str),
    #[error("internal error {0}")]
    InternalError(&'static str),
    #[error("error while invoking an ffi callback: {0}")]
    FfiBindingError(String),
    #[error("application callback {0} threw exception {}with message {2}", .1.clone().map(|s| s + " ").unwrap_or_default())]
    ApplicationCallbackThrewException(&'static str, Option<String>, String),
    #[error("application callback {0} returned error code {1}")]
    ApplicationCallbackReturnedIntegerError(&'static str, i32),

    #[error("invalid sealed sender message {0}")]
    InvalidSealedSenderMessage(String),
    #[error("unknown sealed sender message version {0}")]
    UnknownSealedSenderVersion(u8),
    #[error("self send of a sealed sender message")]
    SealedSenderSelfSend,
}

#[cfg(test)]
mod formatting_tests {
    use super::SignalProtocolError::ApplicationCallbackThrewException;
    #[test]
    fn test_application_callback_threw_named_exception() {
        let err = ApplicationCallbackThrewException(
            "callback_name",
            Some("exception_name".to_owned()),
            "an error message".to_owned(),
        );

        assert_eq!(err.to_string(), "application callback callback_name threw exception exception_name with message an error message")
    }

    #[test]
    fn test_application_callback_threw_unknown_exception() {
        let err =
            ApplicationCallbackThrewException("callback_name", None, "an error message".to_owned());

        assert_eq!(
            err.to_string(),
            "application callback callback_name threw exception with message an error message"
        )
    }
}
