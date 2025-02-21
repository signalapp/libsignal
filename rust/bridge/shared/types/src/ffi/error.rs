//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use attest::enclave::Error as EnclaveError;
use attest::hsm_enclave::Error as HsmEnclaveError;
use device_transfer::Error as DeviceTransferError;
use libsignal_account_keys::Error as PinError;
use libsignal_net::chat::ChatServiceError;
use libsignal_net::infra::ws::WebSocketConnectError;
use libsignal_net::svr3::Error as Svr3Error;
use libsignal_net::ws::WebSocketServiceConnectError;
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use usernames::{UsernameError, UsernameLinkError};
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use super::{FutureCancelled, NullPointerError, UnexpectedPanic};
use crate::support::describe_panic;

#[derive(Debug)]
#[repr(C)]
pub enum SignalErrorCode {
    #[allow(dead_code)]
    UnknownError = 1,
    InvalidState = 2,
    InternalError = 3,
    NullParameter = 4,
    InvalidArgument = 5,
    InvalidType = 6,
    InvalidUtf8String = 7,
    Cancelled = 8,

    ProtobufError = 10,

    LegacyCiphertextVersion = 21,
    UnknownCiphertextVersion = 22,
    UnrecognizedMessageVersion = 23,

    InvalidMessage = 30,
    SealedSenderSelfSend = 31,

    InvalidKey = 40,
    InvalidSignature = 41,
    InvalidAttestationData = 42,

    FingerprintVersionMismatch = 51,
    FingerprintParsingError = 52,

    UntrustedIdentity = 60,

    InvalidKeyIdentifier = 70,

    SessionNotFound = 80,
    InvalidRegistrationId = 81,
    InvalidSession = 82,
    InvalidSenderKeySession = 83,

    DuplicatedMessage = 90,

    CallbackError = 100,

    VerificationFailure = 110,

    UsernameCannotBeEmpty = 120,
    UsernameCannotStartWithDigit = 121,
    UsernameMissingSeparator = 122,
    UsernameBadDiscriminatorCharacter = 123,
    UsernameBadNicknameCharacter = 124,
    UsernameTooShort = 125,
    UsernameTooLong = 126,
    UsernameLinkInvalidEntropyDataLength = 127,
    UsernameLinkInvalid = 128,

    UsernameDiscriminatorCannotBeEmpty = 130,
    UsernameDiscriminatorCannotBeZero = 131,
    UsernameDiscriminatorCannotBeSingleDigit = 132,
    UsernameDiscriminatorCannotHaveLeadingZeros = 133,
    UsernameDiscriminatorTooLarge = 134,

    IoError = 140,
    #[allow(dead_code)]
    InvalidMediaInput = 141,
    #[allow(dead_code)]
    UnsupportedMediaInput = 142,

    ConnectionTimedOut = 143,
    NetworkProtocol = 144,
    RateLimited = 145,
    WebSocket = 146,
    CdsiInvalidToken = 147,
    ConnectionFailed = 148,
    ChatServiceInactive = 149,
    RequestTimedOut = 150,

    SvrDataMissing = 160,
    SvrRestoreFailed = 161,
    SvrRotationMachineTooManySteps = 162,

    AppExpired = 170,
    DeviceDeregistered = 171,

    BackupValidation = 180,
}

pub trait UpcastAsAny {
    fn upcast_as_any(&self) -> &dyn std::any::Any;
}
impl<T: std::any::Any> UpcastAsAny for T {
    fn upcast_as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Error returned when asking for an attribute of an error that doesn't support that attribute.
pub struct WrongErrorKind;

pub trait FfiError: UpcastAsAny + fmt::Debug + Send + 'static {
    fn describe(&self) -> String;
    fn code(&self) -> SignalErrorCode;

    fn provide_address(&self) -> Result<ProtocolAddress, WrongErrorKind> {
        Err(WrongErrorKind)
    }
    fn provide_uuid(&self) -> Result<uuid::Uuid, WrongErrorKind> {
        Err(WrongErrorKind)
    }
    fn provide_retry_after_seconds(&self) -> Result<u32, WrongErrorKind> {
        Err(WrongErrorKind)
    }
    fn provide_tries_remaining(&self) -> Result<u32, WrongErrorKind> {
        Err(WrongErrorKind)
    }
    fn provide_unknown_fields(&self) -> Result<Vec<String>, WrongErrorKind> {
        Err(WrongErrorKind)
    }
}

/// The top-level error type (opaquely) returned to C clients when something goes wrong.
///
/// Ideally this would use [ThinBox][], and then we wouldn't need an extra level of indirection when
/// returning it to C, but unfortunately that isn't stable yet.
///
/// [ThinBox]: https://doc.rust-lang.org/std/boxed/struct.ThinBox.html
#[derive(Debug)]
pub struct SignalFfiError(Box<dyn FfiError + Send>);

impl SignalFfiError {
    pub fn downcast_ref<T: FfiError>(&self) -> Option<&T> {
        (*self.0).upcast_as_any().downcast_ref()
    }
}

/// SignalFfiError is a typed wrapper around a Box, and as such it's reasonable for it to have the
/// same Deref behavior as a Box. All the interesting functionality is present on the [`FfiError`]
/// trait.
impl std::ops::Deref for SignalFfiError {
    type Target = dyn FfiError;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl fmt::Display for SignalFfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.describe())
    }
}

impl<T: FfiError> From<T> for SignalFfiError {
    fn from(mut value: T) -> Self {
        // Special case: if the error being boxed is an IoError containing a SignalProtocolError,
        // extract the SignalProtocolError up front.
        match (&mut value as &mut dyn std::any::Any).downcast_mut::<IoError>() {
            Some(e) => {
                let original_error = (e.kind() == IoErrorKind::Other)
                    .then(|| {
                        e.get_mut()
                            .and_then(|e| e.downcast_mut::<SignalProtocolError>())
                    })
                    .flatten()
                    .map(|e| {
                        // We can't get the inner error out without putting something in
                        // its place, so leave some random (cheap-to-construct) error.
                        // TODO: use IoError::downcast() once it is stabilized
                        // (https://github.com/rust-lang/rust/issues/99262).
                        std::mem::replace(e, SignalProtocolError::InvalidPreKeyId)
                    });
                if let Some(original_error) = original_error {
                    Self(Box::new(original_error))
                } else {
                    Self(Box::new(value))
                }
            }
            None => Self(Box::new(value)),
        }
    }
}

impl FfiError for SignalProtocolError {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> SignalErrorCode {
        match self {
            Self::InvalidArgument(_) => SignalErrorCode::InvalidArgument,
            Self::InvalidState(_, _) => SignalErrorCode::InvalidState,
            Self::InvalidProtobufEncoding => SignalErrorCode::ProtobufError,
            Self::CiphertextMessageTooShort(_)
            | Self::InvalidMessage(_, _)
            | Self::InvalidSealedSenderMessage(_)
            | Self::BadKEMCiphertextLength(_, _) => SignalErrorCode::InvalidMessage,
            Self::LegacyCiphertextVersion(_) => SignalErrorCode::LegacyCiphertextVersion,
            Self::UnrecognizedCiphertextVersion(_) => SignalErrorCode::UnknownCiphertextVersion,
            Self::UnrecognizedMessageVersion(_) | Self::UnknownSealedSenderVersion(_) => {
                SignalErrorCode::UnrecognizedMessageVersion
            }
            Self::FingerprintVersionMismatch(_, _) => SignalErrorCode::FingerprintVersionMismatch,
            Self::FingerprintParsingError => SignalErrorCode::FingerprintParsingError,
            Self::NoKeyTypeIdentifier
            | Self::BadKeyType(_)
            | Self::BadKeyLength(_, _)
            | Self::InvalidMacKeyLength(_)
            | Self::BadKEMKeyType(_)
            | Self::WrongKEMKeyType(_, _)
            | Self::BadKEMKeyLength(_, _) => SignalErrorCode::InvalidKey,
            Self::SignatureValidationFailed => SignalErrorCode::InvalidSignature,
            Self::UntrustedIdentity(_) => SignalErrorCode::UntrustedIdentity,
            Self::InvalidPreKeyId | Self::InvalidSignedPreKeyId | Self::InvalidKyberPreKeyId => {
                SignalErrorCode::InvalidKeyIdentifier
            }
            Self::NoSenderKeyState { .. } | Self::SessionNotFound(_) => {
                SignalErrorCode::SessionNotFound
            }
            Self::InvalidSessionStructure(_) => SignalErrorCode::InvalidSession,
            Self::InvalidSenderKeySession { .. } => SignalErrorCode::InvalidSenderKeySession,
            Self::InvalidRegistrationId(_, _) => SignalErrorCode::InvalidRegistrationId,
            Self::DuplicatedMessage(_, _) => SignalErrorCode::DuplicatedMessage,
            Self::FfiBindingError(_) => SignalErrorCode::InternalError,
            Self::ApplicationCallbackError(_, _) => SignalErrorCode::CallbackError,
            Self::SealedSenderSelfSend => SignalErrorCode::SealedSenderSelfSend,
        }
    }

    fn provide_address(&self) -> Result<ProtocolAddress, WrongErrorKind> {
        match self {
            Self::InvalidRegistrationId(address, _id) => Ok(address.clone()),
            _ => Err(WrongErrorKind),
        }
    }

    fn provide_uuid(&self) -> Result<uuid::Uuid, WrongErrorKind> {
        match self {
            Self::InvalidSenderKeySession { distribution_id } => Ok(*distribution_id),
            _ => Err(WrongErrorKind),
        }
    }
}

impl FfiError for DeviceTransferError {
    fn describe(&self) -> String {
        format!("Device transfer operation failed: {self}")
    }

    fn code(&self) -> SignalErrorCode {
        match self {
            Self::KeyDecodingFailed => SignalErrorCode::InvalidKey,
            Self::InternalError(_) => SignalErrorCode::InternalError,
        }
    }
}

impl FfiError for HsmEnclaveError {
    fn describe(&self) -> String {
        format!("HSM enclave operation failed: {self}")
    }

    fn code(&self) -> SignalErrorCode {
        match self {
            Self::HSMCommunicationError(_) | Self::HSMHandshakeError(_) => {
                SignalErrorCode::InvalidMessage
            }
            Self::TrustedCodeError => SignalErrorCode::UntrustedIdentity,
            Self::InvalidPublicKeyError => SignalErrorCode::InvalidKey,
            Self::InvalidCodeHashError => SignalErrorCode::InvalidArgument,
            Self::InvalidBridgeStateError => SignalErrorCode::InvalidState,
        }
    }
}

impl FfiError for EnclaveError {
    fn describe(&self) -> String {
        format!("SGX operation failed: {self}")
    }

    fn code(&self) -> SignalErrorCode {
        match self {
            Self::AttestationError(_) | Self::NoiseError(_) | Self::NoiseHandshakeError(_) => {
                SignalErrorCode::InvalidMessage
            }
            Self::AttestationDataError { .. } => SignalErrorCode::InvalidAttestationData,
            Self::InvalidBridgeStateError => SignalErrorCode::InvalidState,
        }
    }
}

impl FfiError for PinError {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> SignalErrorCode {
        match self {
            Self::Argon2Error(_) | Self::DecodingError(_) | Self::MrenclaveLookupError => {
                SignalErrorCode::InvalidArgument
            }
        }
    }
}

impl FfiError for SignalCryptoError {
    fn describe(&self) -> String {
        format!("Cryptographic operation failed: {self}")
    }

    fn code(&self) -> SignalErrorCode {
        match self {
            Self::UnknownAlgorithm(_, _)
            | Self::InvalidKeySize
            | Self::InvalidNonceSize
            | Self::InvalidInputSize => SignalErrorCode::InvalidArgument,
            Self::InvalidTag => SignalErrorCode::InvalidMessage,
        }
    }
}

impl FfiError for ZkGroupVerificationFailure {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> SignalErrorCode {
        SignalErrorCode::VerificationFailure
    }
}

impl FfiError for ZkGroupDeserializationFailure {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> SignalErrorCode {
        SignalErrorCode::InvalidType
    }
}

impl FfiError for UsernameError {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> SignalErrorCode {
        match self {
            Self::MissingSeparator => SignalErrorCode::UsernameMissingSeparator,
            Self::NicknameCannotBeEmpty => SignalErrorCode::UsernameCannotBeEmpty,
            Self::NicknameCannotStartWithDigit => SignalErrorCode::UsernameCannotStartWithDigit,
            Self::BadNicknameCharacter => SignalErrorCode::UsernameBadNicknameCharacter,
            Self::NicknameTooShort => SignalErrorCode::UsernameTooShort,
            Self::NicknameTooLong => SignalErrorCode::UsernameTooLong,
            Self::DiscriminatorCannotBeEmpty => SignalErrorCode::UsernameDiscriminatorCannotBeEmpty,
            Self::DiscriminatorCannotBeZero => SignalErrorCode::UsernameDiscriminatorCannotBeZero,
            Self::DiscriminatorCannotBeSingleDigit => {
                SignalErrorCode::UsernameDiscriminatorCannotBeSingleDigit
            }
            Self::DiscriminatorCannotHaveLeadingZeros => {
                SignalErrorCode::UsernameDiscriminatorCannotHaveLeadingZeros
            }
            Self::BadDiscriminatorCharacter => SignalErrorCode::UsernameBadDiscriminatorCharacter,
            Self::DiscriminatorTooLarge => SignalErrorCode::UsernameDiscriminatorTooLarge,
        }
    }
}

impl FfiError for usernames::ProofVerificationFailure {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> SignalErrorCode {
        SignalErrorCode::VerificationFailure
    }
}

impl FfiError for UsernameLinkError {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> SignalErrorCode {
        match self {
            Self::InputDataTooLong => SignalErrorCode::UsernameTooLong,
            Self::InvalidEntropyDataLength => SignalErrorCode::UsernameLinkInvalidEntropyDataLength,
            Self::UsernameLinkDataTooShort
            | Self::HmacMismatch
            | Self::BadCiphertext
            | Self::InvalidDecryptedDataStructure => SignalErrorCode::UsernameLinkInvalid,
        }
    }
}

impl FfiError for IoError {
    fn describe(&self) -> String {
        format!("IO error: {self}")
    }

    fn code(&self) -> SignalErrorCode {
        // Parallels the unwrapping that happens when converting to a boxed SignalFfiError.
        (self.kind() == IoErrorKind::Other)
            .then(|| {
                Some(
                    self.get_ref()?
                        .downcast_ref::<SignalProtocolError>()?
                        .code(),
                )
            })
            .flatten()
            .unwrap_or(SignalErrorCode::IoError)
    }
}

impl FfiError for libsignal_net::cdsi::LookupError {
    fn describe(&self) -> String {
        match self {
            Self::CdsiProtocol(_)
            | Self::EnclaveProtocol(_)
            | Self::InvalidResponse
            | Self::ParseError
            | Self::Server { .. } => {
                format!("Protocol error: {self}")
            }
            Self::AttestationError(e) => e.describe(),
            Self::RateLimited {
                retry_after_seconds,
            } => format!("Rate limited; try again after {retry_after_seconds}s"),
            Self::InvalidToken => "CDSI request token was invalid".to_owned(),
            Self::ConnectTransport(e) => format!("IO error: {e}"),
            Self::WebSocket(e) => format!("WebSocket error: {e}"),
            Self::ConnectionTimedOut => "Connect timed out".to_owned(),
            Self::InvalidArgument { .. } => format!("invalid argument: {self}"),
        }
    }

    fn code(&self) -> SignalErrorCode {
        match self {
            Self::CdsiProtocol(_)
            | Self::EnclaveProtocol(_)
            | Self::InvalidResponse
            | Self::ParseError
            | Self::Server { .. } => SignalErrorCode::NetworkProtocol,
            Self::AttestationError(e) => e.code(),
            Self::RateLimited { .. } => SignalErrorCode::RateLimited,
            Self::InvalidToken => SignalErrorCode::CdsiInvalidToken,
            Self::ConnectTransport(_) => SignalErrorCode::IoError,
            Self::WebSocket(_) => SignalErrorCode::WebSocket,
            Self::ConnectionTimedOut => SignalErrorCode::ConnectionTimedOut,
            Self::InvalidArgument { .. } => SignalErrorCode::InvalidArgument,
        }
    }

    fn provide_retry_after_seconds(&self) -> Result<u32, WrongErrorKind> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => Ok(*retry_after_seconds),
            _ => Err(WrongErrorKind),
        }
    }
}

impl FfiError for Svr3Error {
    fn describe(&self) -> String {
        match self {
            Self::Connect(WebSocketServiceConnectError::Connect(
                WebSocketConnectError::Timeout,
                _,
            ))
            | Self::ConnectionTimedOut => "Connect timed out".to_owned(),
            Self::Connect(WebSocketServiceConnectError::Connect(
                WebSocketConnectError::Transport(e),
                _,
            )) => {
                format!("IO error: {e}")
            }
            Self::Connect(
                e @ (WebSocketServiceConnectError::Connect(
                    WebSocketConnectError::WebSocketError(_),
                    _,
                )
                | WebSocketServiceConnectError::RejectedByServer { .. }),
            ) => {
                format!("WebSocket error: {e}")
            }
            Self::Service(e) => format!("WebSocket error: {e}"),
            Self::Protocol(e) => format!("Protocol error: {e}"),
            Self::AttestationError(inner) => inner.describe(),
            Self::RequestFailed(_)
            | Self::RestoreFailed(_)
            | Self::DataMissing
            | Self::RotationMachineTooManySteps => {
                format!("SVR error: {self}")
            }
        }
    }

    fn code(&self) -> SignalErrorCode {
        match self {
            Self::Connect(e) => match e {
                WebSocketServiceConnectError::RejectedByServer { .. } => SignalErrorCode::WebSocket,
                WebSocketServiceConnectError::Connect(e, _) => match e {
                    WebSocketConnectError::Transport(_) => SignalErrorCode::IoError,
                    WebSocketConnectError::Timeout => SignalErrorCode::ConnectionTimedOut,
                    WebSocketConnectError::WebSocketError(_) => SignalErrorCode::WebSocket,
                },
            },
            Self::Service(_) => SignalErrorCode::WebSocket,
            Self::ConnectionTimedOut => SignalErrorCode::ConnectionTimedOut,
            Self::AttestationError(inner) => inner.code(),
            Self::Protocol(_) => SignalErrorCode::NetworkProtocol,
            Self::RequestFailed(_) => SignalErrorCode::UnknownError,
            Self::RestoreFailed(_) => SignalErrorCode::SvrRestoreFailed,
            Self::DataMissing => SignalErrorCode::SvrDataMissing,
            Self::RotationMachineTooManySteps => SignalErrorCode::SvrRotationMachineTooManySteps,
        }
    }

    fn provide_tries_remaining(&self) -> Result<u32, WrongErrorKind> {
        match self {
            Self::RestoreFailed(tries_remaining) => Ok(*tries_remaining),
            _ => Err(WrongErrorKind),
        }
    }
}

impl FfiError for ChatServiceError {
    fn describe(&self) -> String {
        match self {
            Self::WebSocket(e) => format!("WebSocket error: {e}"),
            Self::AllConnectionRoutesFailed | Self::InvalidConnectionConfiguration => {
                "Connection failed".to_owned()
            }
            Self::UnexpectedFrameReceived
            | Self::ServerRequestMissingId
            | Self::IncomingDataInvalid => format!("Protocol error: {self}"),
            Self::RequestHasInvalidHeader => {
                format!("internal error: {self}")
            }
            Self::RequestSendTimedOut => "Request timed out".to_string(),
            Self::TimeoutEstablishingConnection => "Connect timed out".to_owned(),
            Self::Disconnected => "Chat service disconnected".to_owned(),
            Self::AppExpired => "App expired".to_owned(),
            Self::DeviceDeregistered => "Device deregistered or delinked".to_owned(),
            Self::RetryLater {
                retry_after_seconds,
            } => format!("Rate limited; try again after {retry_after_seconds}s"),
        }
    }

    fn code(&self) -> SignalErrorCode {
        match self {
            Self::WebSocket(_) => SignalErrorCode::WebSocket,
            Self::AllConnectionRoutesFailed { .. } | Self::InvalidConnectionConfiguration => {
                SignalErrorCode::ConnectionFailed
            }
            Self::UnexpectedFrameReceived
            | Self::ServerRequestMissingId
            | Self::IncomingDataInvalid => SignalErrorCode::NetworkProtocol,
            Self::RequestHasInvalidHeader => SignalErrorCode::InternalError,
            Self::RequestSendTimedOut => SignalErrorCode::RequestTimedOut,
            Self::TimeoutEstablishingConnection => SignalErrorCode::ConnectionTimedOut,
            Self::Disconnected => SignalErrorCode::ChatServiceInactive,
            Self::AppExpired => SignalErrorCode::AppExpired,
            Self::DeviceDeregistered => SignalErrorCode::DeviceDeregistered,
            Self::RetryLater { .. } => SignalErrorCode::RateLimited,
        }
    }
    fn provide_retry_after_seconds(&self) -> Result<u32, WrongErrorKind> {
        match self {
            ChatServiceError::RetryLater {
                retry_after_seconds,
            } => Ok(*retry_after_seconds),
            _ => Err(WrongErrorKind),
        }
    }
}

impl FfiError for http::uri::InvalidUri {
    fn describe(&self) -> String {
        format!("invalid argument: {self}")
    }

    fn code(&self) -> SignalErrorCode {
        SignalErrorCode::InvalidArgument
    }
}

#[cfg(feature = "signal-media")]
impl FfiError for signal_media::sanitize::mp4::Error {
    fn describe(&self) -> String {
        match self {
            Self::Io(e) => e.describe(),
            Self::Parse(e) => format!("Mp4 sanitizer failed to parse mp4 file: {e}"),
        }
    }

    fn code(&self) -> SignalErrorCode {
        use signal_media::sanitize::mp4::ParseError;
        match self {
            Self::Io(e) => e.code(),
            Self::Parse(e) => match e.kind {
                ParseError::InvalidBoxLayout { .. }
                | ParseError::InvalidInput { .. }
                | ParseError::MissingRequiredBox { .. }
                | ParseError::TruncatedBox => SignalErrorCode::InvalidMediaInput,

                ParseError::UnsupportedBoxLayout { .. }
                | ParseError::UnsupportedBox { .. }
                | ParseError::UnsupportedFormat { .. } => SignalErrorCode::UnsupportedMediaInput,
            },
        }
    }
}

#[cfg(feature = "signal-media")]
impl FfiError for signal_media::sanitize::webp::Error {
    fn describe(&self) -> String {
        match self {
            Self::Io(e) => e.describe(),
            Self::Parse(e) => format!("WebP sanitizer failed to parse webp file: {e}"),
        }
    }

    fn code(&self) -> SignalErrorCode {
        use signal_media::sanitize::webp::ParseError;
        match self {
            Self::Io(e) => e.code(),
            Self::Parse(e) => match e.kind {
                ParseError::InvalidChunkLayout { .. }
                | ParseError::InvalidInput { .. }
                | ParseError::InvalidVp8lPrefixCode { .. }
                | ParseError::MissingRequiredChunk { .. }
                | ParseError::TruncatedChunk => SignalErrorCode::InvalidMediaInput,

                ParseError::UnsupportedChunk { .. } | ParseError::UnsupportedVp8lVersion { .. } => {
                    SignalErrorCode::UnsupportedMediaInput
                }
            },
        }
    }
}

impl FfiError for libsignal_message_backup::ReadError {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> SignalErrorCode {
        SignalErrorCode::BackupValidation
    }

    fn provide_unknown_fields(&self) -> Result<Vec<String>, WrongErrorKind> {
        Ok(self
            .found_unknown_fields
            .iter()
            .map(ToString::to_string)
            .collect())
    }
}

impl FfiError for NullPointerError {
    fn describe(&self) -> String {
        "null pointer".to_owned()
    }

    fn code(&self) -> SignalErrorCode {
        SignalErrorCode::NullParameter
    }
}

impl FfiError for UnexpectedPanic {
    fn describe(&self) -> String {
        format!("unexpected panic: {}", describe_panic(&self.0))
    }

    fn code(&self) -> SignalErrorCode {
        SignalErrorCode::InternalError
    }
}

impl FfiError for std::str::Utf8Error {
    fn describe(&self) -> String {
        "invalid UTF8 string".to_owned()
    }

    fn code(&self) -> SignalErrorCode {
        SignalErrorCode::InvalidUtf8String
    }
}

impl FfiError for FutureCancelled {
    fn describe(&self) -> String {
        "cancelled".to_owned()
    }

    fn code(&self) -> SignalErrorCode {
        SignalErrorCode::Cancelled
    }
}

pub type SignalFfiResult<T> = Result<T, SignalFfiError>;

/// Represents an error returned by a callback, following the C conventions that 0 means "success".
#[derive(Debug)]
pub struct CallbackError {
    value: std::num::NonZeroI32,
}

impl CallbackError {
    /// Returns `Ok(())` if `value` is zero; otherwise, wraps the value in `Self` as an error.
    pub fn check(value: i32) -> Result<(), Self> {
        match std::num::NonZeroI32::try_from(value).ok() {
            None => Ok(()),
            Some(value) => Err(Self { value }),
        }
    }
}

impl fmt::Display for CallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error code {}", self.value)
    }
}

impl std::error::Error for CallbackError {}
