//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Errors that may occur during various stages of the Signal Protocol.

#![warn(missing_docs)]

use crate::curve::KeyType;

use displaydoc::Display;
use thiserror::Error;
use uuid::Uuid;

use std::panic::UnwindSafe;

#[cfg(doc)]
pub use crate::{
    address::ProtocolAddress,
    curve::{PrivateKey, PublicKey},
    group_cipher::{group_decrypt, group_encrypt},
    protocol::{SenderKeyMessage, SignalMessage, CIPHERTEXT_MESSAGE_CURRENT_VERSION},
    sealed_sender::{sealed_sender_decrypt, sealed_sender_multi_recipient_encrypt},
    sender_keys::SenderKeyRecord,
    session_cipher::{message_decrypt, message_encrypt},
    state::{PreKeyId, PreKeyRecord, SignedPreKeyId, SignedPreKeyRecord},
    storage::{IdentityKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore},
};

/// Return type for all fallible operations in this crate.
pub type Result<T> = std::result::Result<T, SignalProtocolError>;

/// Error states recognized by the Signal Protocol.
#[derive(Debug, Display, Error)]
#[ignore_extra_doc_attributes]
pub enum SignalProtocolError {
    /// invalid argument: {0}
    ///
    /// Raised if an invalid argument is provided to any Signal API methods.
    ///
    /// Prefer to use lifetimes, static-sized slices, and dedicated wrapper structs in API
    /// signatures to minimize the need to raise this error to FFI boundaries.
    InvalidArgument(String),
    /// invalid state for call to {0} to succeed: {1}
    ///
    /// Raised if some optional value was missing before performing some operation which needed it.
    ///
    /// Prefer to avoid returning [std::result::Result] and [Option] from struct methods in cases
    /// where they're not necessary for trait polymorphism, as well as using dedicated wrapper
    /// structs in API signatures, to minimize the need to raise this error.
    InvalidState(&'static str, String),

    /// protobuf encoding was invalid
    ///
    /// Raised if a field in a protobuf is invalid in some way.
    ///
    /// Prefer to raise [Self::InvalidState] except in methods which directly decode protobufs.
    InvalidProtobufEncoding,

    /// ciphertext serialized bytes were too short <{0}>
    ///
    /// Raised if some ciphertext was deserialized from a too-small slice.
    ///
    /// Prefer to make API method signatures and wrapper structs consume and produce static-sized
    /// byte slices to minimize the need to raise this error.
    CiphertextMessageTooShort(usize),
    /// ciphertext version was too old <{0}>
    ///
    /// Raised if the ciphertext version decoded from a protobuf is older than this client.
    ///
    /// The current client's ciphertext version is at [CIPHERTEXT_MESSAGE_CURRENT_VERSION].
    LegacyCiphertextVersion(u8),
    /// ciphertext version was unrecognized <{0}>
    ///
    /// Raised if the ciphertext version decoded from a protobuf is newer than this client.
    ///
    /// The current client's ciphertext version is at [CIPHERTEXT_MESSAGE_CURRENT_VERSION].
    UnrecognizedCiphertextVersion(u8),
    /// unrecognized message version <{0}>
    ///
    /// Raised if the ciphertext version decoded from a protobuf fails to match the cached version
    /// for the message chain that message originates from.
    ///
    /// *TODO: This case should wrap the same numeric type as [Self::LegacyCiphertextVersion] and
    /// [Self::UnrecognizedCiphertextVersion]. This dissonance is addressed in
    /// <https://github.com/signalapp/libsignal-client/pull/289>.*
    UnrecognizedMessageVersion(u32),

    /// fingerprint version number mismatch them {0} us {1}
    ///
    /// Raised if a fingerprint version decoded from a protobuf has an unexpected value.
    FingerprintVersionMismatch(u32, u32),
    /// fingerprint parsing error
    ///
    /// Raised if a field in a fingerprint protobuf is invalid in some way.
    ///
    /// Similar to [Self::InvalidProtobufEncoding].
    FingerprintParsingError,

    /// no key type identifier
    ///
    /// Raised if a [PublicKey] is deserialized from an empty slice.
    ///
    /// Prefer to use static-sized slices in API method signatures and struct fields to minimize the
    /// need to raise this error.
    NoKeyTypeIdentifier,
    /// bad key type <{0:#04x}>
    ///
    /// Raised if a [KeyType] decoded from a [u8] has an unrecognized value.
    BadKeyType(u8),
    /// bad key length <{1}> for key with type <{0}>
    ///
    /// Raised if a [PublicKey] or [PrivateKey] is deserialized from a slice of incorrect length.
    ///
    /// Prefer to use static-sized slices in API method signatures and struct fields to minimize the
    /// need to raise this error.
    BadKeyLength(KeyType, usize),

    /// invalid signature detected
    ///
    /// Raised if signature validation fails for a [SignedPreKeyRecord] or a [SenderKeyMessage].
    SignatureValidationFailed,

    /// untrusted identity for address {0}
    ///
    /// Raised if an identity verification check fails in [message_encrypt] or [message_decrypt].
    UntrustedIdentity(crate::ProtocolAddress),

    /// invalid prekey identifier
    ///
    /// Raised if a [PreKeyId] could not be resolved to a [PreKeyRecord] by a [PreKeyStore].
    InvalidPreKeyId,
    /// invalid signed prekey identifier
    ///
    /// Raised if a [SignedPreKeyId] could not be resolved to a [SignedPreKeyRecord] by
    /// a [SignedPreKeyStore].
    InvalidSignedPreKeyId,

    /// invalid MAC key length <{0}>
    ///
    /// Raised if a MAC key is deserialized from an incorrectly-sized slice.
    ///
    /// Prefer to use static-sized slices in API method signatures and struct fields to minimize the
    /// need to raise this error.
    InvalidMacKeyLength(usize),

    /// missing sender key state for distribution ID {distribution_id}
    ///
    /// Raised if a [SenderKeyStore] is unable to locate a [SenderKeyRecord] for a given
    /// *([ProtocolAddress], [Uuid])* pair in [group_encrypt] or [group_decrypt].
    NoSenderKeyState {
        /// Unique identifier for the sender key session.
        distribution_id: Uuid,
    },

    /// session with {0} not found
    ///
    /// Raised if an [IdentityKeyStore] does not contain an entry for a [ProtocolAddress], or
    /// alternately if a [SessionStore] does not contain a session for a given [ProtocolAddress].
    SessionNotFound(crate::ProtocolAddress),
    /// invalid session: {0}
    ///
    /// Raised if a [SessionStore] does not contain a remote identity key to validate.
    ///
    /// Similar to [Self::InvalidState].
    InvalidSessionStructure(&'static str),
    /// invalid sender key session with distribution ID {distribution_id}
    ///
    /// Raised if a [SenderKeyStore] could not load the session for the given ID.
    ///
    /// Similar to [Self::NoSenderKeyState].
    InvalidSenderKeySession {
        /// Unique identifier for the sender key session.
        distribution_id: Uuid,
    },
    /// session for {0} has invalid registration ID {1:X}
    ///
    /// Raised if a sealed sender message has a registration id that doesn't map to any
    /// known session.
    InvalidRegistrationId(crate::ProtocolAddress, u32),

    /// message with old counter {0} / {1}
    ///
    /// Raised if the same message is decrypted twice so it can be discarded.
    DuplicatedMessage(u32, u32),
    /// invalid {0:?} message: {1}
    ///
    /// Raised if a [SignalMessage] could not be decrypted or some field had an unexpected value.
    ///
    /// *TODO: what differentiates this from [Self::CiphertextMessageTooShort]?*
    InvalidMessage(crate::CiphertextMessageType, &'static str),

    /// error while invoking an ffi callback: {0}
    ///
    /// Raised to propagate an error from an FFI callback.
    FfiBindingError(String),
    /// error in method call '{0}': {1}
    ///
    /// Raised to propagate an error through to an FFI exception along with a boxed handle.
    ApplicationCallbackError(
        &'static str,
        #[source] Box<dyn std::error::Error + Send + Sync + UnwindSafe + 'static>,
    ),

    /// invalid sealed sender message: {0}
    ///
    /// Raised if an [crate::sealed_sender::UnidentifiedSenderMessage] could not be
    /// deserialized successfully.
    ///
    /// *TODO: this sounds a lot like [Self::InvalidProtobufEncoding] or [Self::UntrustedIdentity]?*
    InvalidSealedSenderMessage(String),
    /// unknown sealed sender message version {0}
    ///
    /// Raised if an version decoded from a [crate::sealed_sender::UnidentifiedSenderMessage]
    /// was unrecognized.
    UnknownSealedSenderVersion(u8),
    /// self send of a sealed sender message
    ///
    /// Raised if [sealed_sender_decrypt] finds that the message came from this exact client.
    SealedSenderSelfSend,
}
