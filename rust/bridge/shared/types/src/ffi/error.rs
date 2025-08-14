//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::fmt;

use attest::enclave::Error as EnclaveError;
use attest::hsm_enclave::Error as HsmEnclaveError;
use device_transfer::Error as DeviceTransferError;
use libsignal_account_keys::Error as PinError;
use libsignal_net_chat::api::registration::{RegistrationLock, VerificationCodeNotDeliverable};
use libsignal_net_chat::api::RateLimitChallenge;
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use usernames::{UsernameError, UsernameLinkError};
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use super::{FutureCancelled, NullPointerError, UnexpectedPanic};
use crate::support::describe_panic;

#[derive(Debug, Clone, Copy)]
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
    InvalidProtocolAddress = 84,

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
    RateLimitChallenge = 151,

    SvrDataMissing = 160,
    SvrRestoreFailed = 161,
    SvrRotationMachineTooManySteps = 162,
    SvrRequestFailed = 163,

    AppExpired = 170,
    DeviceDeregistered = 171,
    ConnectionInvalidated = 172,
    ConnectedElsewhere = 173,

    BackupValidation = 180,

    RegistrationInvalidSessionId = 190,
    RegistrationUnknown = 192,
    RegistrationSessionNotFound = 193,
    RegistrationNotReadyForVerification = 194,
    RegistrationSendVerificationCodeFailed = 195,
    RegistrationCodeNotDeliverable = 196,
    RegistrationSessionUpdateRejected = 197,
    RegistrationCredentialsCouldNotBeParsed = 198,
    RegistrationDeviceTransferPossible = 199,
    RegistrationRecoveryVerificationFailed = 200,
    RegistrationLock = 201,

    KeyTransparencyError = 210,
    KeyTransparencyVerificationFailed = 211,
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

pub struct FingerprintVersions {
    pub theirs: u32,
    pub ours: u32,
}

/// A trait for *bridged* error representations specifically.
///
/// This should be used for any errors that need to provide additional properties *themselves,* but
/// if they merely delegate to another error, or have no additional properties at all, prefer
/// implementing [`IntoFfiError`] instead, using [`SimpleError`] for the cases that don't need
/// special handling.
pub trait FfiError: UpcastAsAny + fmt::Debug + Send + 'static {
    fn describe(&self) -> Cow<'_, str>;
    fn code(&self) -> SignalErrorCode;

    fn provide_address(&self) -> Result<ProtocolAddress, WrongErrorKind> {
        Err(WrongErrorKind)
    }
    fn provide_uuid(&self) -> Result<uuid::Uuid, WrongErrorKind> {
        Err(WrongErrorKind)
    }
    fn provide_invalid_address(&self) -> Result<(&str, u32), WrongErrorKind> {
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
    fn provide_registration_code_not_deliverable(
        &self,
    ) -> Result<&VerificationCodeNotDeliverable, WrongErrorKind> {
        Err(WrongErrorKind)
    }
    fn provide_registration_lock(&self) -> Result<&RegistrationLock, WrongErrorKind> {
        Err(WrongErrorKind)
    }
    fn provide_rate_limit_challenge(&self) -> Result<&RateLimitChallenge, WrongErrorKind> {
        Err(WrongErrorKind)
    }
    fn provide_fingerprint_versions(&self) -> Result<FingerprintVersions, WrongErrorKind> {
        Err(WrongErrorKind)
    }
}

/// An [`FfiError`] that only has a code and message.
#[derive(Debug)]
struct SimpleError {
    code: SignalErrorCode,
    message: Cow<'static, str>,
}

impl FfiError for SimpleError {
    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.message)
    }

    fn code(&self) -> SignalErrorCode {
        self.code
    }
}

impl SimpleError {
    fn new(code: SignalErrorCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            message: message.into(),
        }
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

    #[cold]
    pub fn into_raw_box_for_ffi(self) -> *mut Self {
        Box::into_raw(Box::new(self))
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

/// A slightly more convenient version of `From`/`Into` for [`SignalFfiError`].
///
/// We have a lot of errors, so the convenience is worth it. The main improvement is that the return
/// type only has to make it to the `FfiError` state.
pub trait IntoFfiError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError>;
}

impl<T: FfiError> IntoFfiError for T {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        SignalFfiError(Box::new(self))
    }
}

impl<T: IntoFfiError> From<T> for SignalFfiError {
    fn from(value: T) -> Self {
        value.into_ffi_error().into()
    }
}

impl FfiError for SignalProtocolError {
    fn describe(&self) -> Cow<'_, str> {
        self.to_string().into()
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
            Self::InvalidProtocolAddress { .. } => SignalErrorCode::InvalidProtocolAddress,
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
    fn provide_invalid_address(&self) -> Result<(&str, u32), WrongErrorKind> {
        match self {
            Self::InvalidProtocolAddress { name, device_id } => Ok((name, *device_id)),
            _ => Err(WrongErrorKind),
        }
    }

    fn provide_fingerprint_versions(&self) -> Result<FingerprintVersions, WrongErrorKind> {
        match self {
            Self::FingerprintVersionMismatch(theirs, ours) => Ok(FingerprintVersions {
                theirs: *theirs,
                ours: *ours,
            }),
            _ => Err(WrongErrorKind),
        }
    }
}

impl IntoFfiError for DeviceTransferError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        let code = match self {
            Self::KeyDecodingFailed => SignalErrorCode::InvalidKey,
            Self::InternalError(_) => SignalErrorCode::InternalError,
        };
        SimpleError::new(code, format!("Device transfer operation failed: {self}"))
    }
}

impl IntoFfiError for HsmEnclaveError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        let code = match self {
            Self::HSMCommunicationError(_) | Self::HSMHandshakeError(_) => {
                SignalErrorCode::InvalidMessage
            }
            Self::TrustedCodeError => SignalErrorCode::UntrustedIdentity,
            Self::InvalidPublicKeyError => SignalErrorCode::InvalidKey,
            Self::InvalidCodeHashError => SignalErrorCode::InvalidArgument,
            Self::InvalidBridgeStateError => SignalErrorCode::InvalidState,
        };
        SimpleError::new(code, format!("HSM enclave operation failed: {self}"))
    }
}

// Kept as an FfiError so other FfiErrors can delegate to it.
impl FfiError for EnclaveError {
    fn describe(&self) -> Cow<'_, str> {
        format!("SGX operation failed: {self}").into()
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

impl IntoFfiError for PinError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        let code = match self {
            Self::Argon2Error(_) | Self::DecodingError(_) | Self::MrenclaveLookupError => {
                SignalErrorCode::InvalidArgument
            }
        };
        SimpleError::new(code, self.to_string())
    }
}

impl IntoFfiError for SignalCryptoError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        let code = match self {
            Self::UnknownAlgorithm(_, _)
            | Self::InvalidKeySize
            | Self::InvalidNonceSize
            | Self::InvalidInputSize => SignalErrorCode::InvalidArgument,
            Self::InvalidTag => SignalErrorCode::InvalidMessage,
        };
        SimpleError::new(code, format!("Cryptographic operation failed: {self}"))
    }
}

impl IntoFfiError for ZkGroupVerificationFailure {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        SimpleError::new(SignalErrorCode::VerificationFailure, self.to_string())
    }
}

impl IntoFfiError for ZkGroupDeserializationFailure {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        SimpleError::new(SignalErrorCode::InvalidType, self.to_string())
    }
}

impl IntoFfiError for UsernameError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        let code = match self {
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
        };
        SimpleError::new(code, self.to_string())
    }
}

impl IntoFfiError for usernames::ProofVerificationFailure {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        SimpleError::new(SignalErrorCode::VerificationFailure, self.to_string())
    }
}

impl IntoFfiError for UsernameLinkError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        let code = match self {
            Self::InputDataTooLong => SignalErrorCode::UsernameTooLong,
            Self::InvalidEntropyDataLength => SignalErrorCode::UsernameLinkInvalidEntropyDataLength,
            Self::UsernameLinkDataTooShort
            | Self::HmacMismatch
            | Self::BadCiphertext
            | Self::InvalidDecryptedDataStructure => SignalErrorCode::UsernameLinkInvalid,
        };
        SimpleError::new(code, self.to_string())
    }
}

impl IntoFfiError for std::io::Error {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        // Special case: if the error being boxed is an IoError containing a SignalProtocolError,
        // extract the SignalProtocolError up front.
        match self.downcast::<SignalProtocolError>() {
            Ok(inner) => inner.into_ffi_error().into(),
            Err(original) => {
                SimpleError::new(SignalErrorCode::IoError, format!("IO error: {original}")).into()
            }
        }
    }
}

impl IntoFfiError for libsignal_net::cdsi::LookupError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        let result: SignalFfiError = match self {
            Self::CdsiProtocol(_)
            | Self::EnclaveProtocol(_)
            | Self::InvalidResponse
            | Self::ParseError
            | Self::Server { .. } => SimpleError::new(
                SignalErrorCode::NetworkProtocol,
                format!("Protocol error: {self}"),
            )
            .into(),
            Self::AttestationError(inner) => inner.into(),
            Self::RateLimited(inner) => inner.into(),
            Self::InvalidToken => SimpleError::new(
                SignalErrorCode::CdsiInvalidToken,
                "CDSI request token was invalid",
            )
            .into(),
            Self::ConnectTransport(e) => {
                SimpleError::new(SignalErrorCode::IoError, format!("IO error: {e}")).into()
            }
            Self::WebSocket(e) => {
                SimpleError::new(SignalErrorCode::WebSocket, format!("WebSocket error: {e}")).into()
            }
            Self::AllConnectionAttemptsFailed => SimpleError::new(
                SignalErrorCode::ConnectionFailed,
                "No connection attempts succeeded before timeout",
            )
            .into(),
            Self::InvalidArgument { .. } => SimpleError::new(
                SignalErrorCode::InvalidArgument,
                format!("invalid argument: {self}"),
            )
            .into(),
        };
        result
    }
}

impl IntoFfiError for libsignal_net::chat::ConnectError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        match self {
            Self::WebSocket(e) => {
                SimpleError::new(SignalErrorCode::WebSocket, format!("WebSocket error: {e}")).into()
            }
            Self::AllAttemptsFailed { .. } | Self::InvalidConnectionConfiguration => {
                SimpleError::new(SignalErrorCode::ConnectionFailed, "Connection failed").into()
            }
            Self::Timeout => {
                SimpleError::new(SignalErrorCode::ConnectionTimedOut, "Connect timed out").into()
            }
            Self::AppExpired => SimpleError::new(SignalErrorCode::AppExpired, "App expired").into(),
            Self::DeviceDeregistered => SimpleError::new(
                SignalErrorCode::DeviceDeregistered,
                "Device deregistered or delinked",
            )
            .into(),
            Self::RetryLater(retry_later) => retry_later.into_ffi_error().into(),
        }
    }
}

impl FfiError for libsignal_net::infra::errors::RetryLater {
    fn code(&self) -> SignalErrorCode {
        SignalErrorCode::RateLimited
    }

    fn describe(&self) -> Cow<'_, str> {
        let Self {
            retry_after_seconds,
        } = self;
        format!("Rate limited; try again after {retry_after_seconds}s").into()
    }

    fn provide_retry_after_seconds(&self) -> Result<u32, WrongErrorKind> {
        Ok(self.retry_after_seconds)
    }
}

impl IntoFfiError for libsignal_net::chat::SendError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        match self {
            Self::WebSocket(e) => {
                SimpleError::new(SignalErrorCode::WebSocket, format!("WebSocket error: {e}"))
            }
            Self::IncomingDataInvalid => SimpleError::new(
                SignalErrorCode::NetworkProtocol,
                format!("Protocol error: {self}"),
            ),
            Self::RequestHasInvalidHeader => SimpleError::new(
                SignalErrorCode::InternalError,
                format!("internal error: {self}"),
            ),
            Self::RequestTimedOut => {
                SimpleError::new(SignalErrorCode::RequestTimedOut, "Request timed out")
            }
            Self::Disconnected => SimpleError::new(
                SignalErrorCode::ChatServiceInactive,
                "Chat service disconnected",
            ),
            Self::ConnectionInvalidated => SimpleError::new(
                SignalErrorCode::ConnectionInvalidated,
                "Connection invalidated",
            ),
            Self::ConnectedElsewhere => {
                SimpleError::new(SignalErrorCode::ConnectedElsewhere, "Connected elsewhere")
            }
        }
    }
}

impl IntoFfiError for libsignal_net_chat::api::DisconnectedError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        let code = match self {
            Self::ConnectedElsewhere => SignalErrorCode::ConnectedElsewhere,
            Self::ConnectionInvalidated => SignalErrorCode::ConnectionInvalidated,
            Self::Transport { .. } => SignalErrorCode::NetworkProtocol,
            Self::Closed => SignalErrorCode::ChatServiceInactive,
        };
        SimpleError::new(code, self.to_string())
    }
}

impl IntoFfiError for crate::keytrans::BridgeError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        use libsignal_net_chat::api::RequestError;
        let message = self.to_string();
        let code = match self.into() {
            RequestError::Disconnected(inner) => return inner.into_ffi_error().into(),
            RequestError::Timeout => SignalErrorCode::RequestTimedOut,
            RequestError::Other(libsignal_net_chat::api::keytrans::Error::VerificationFailed(
                inner,
            )) => match inner {
                libsignal_keytrans::Error::VerificationFailed(_) => {
                    SignalErrorCode::KeyTransparencyVerificationFailed
                }
                libsignal_keytrans::Error::RequiredFieldMissing(_)
                | libsignal_keytrans::Error::BadData(_) => SignalErrorCode::KeyTransparencyError,
            },
            // TODO: Consider being more consistent with other APIs for RetryLater and
            // ServerSideError. (Challenge shouldn't happen in practice.)
            RequestError::RetryLater(_)
            | RequestError::Challenge { .. }
            | RequestError::ServerSideError
            | RequestError::Unexpected { .. }
            | RequestError::Other(_) => SignalErrorCode::KeyTransparencyError,
        };
        SimpleError::new(code, message).into()
    }
}

impl FfiError for RateLimitChallenge {
    fn describe(&self) -> Cow<'_, str> {
        self.to_string().into()
    }

    fn code(&self) -> SignalErrorCode {
        SignalErrorCode::RateLimitChallenge
    }
    fn provide_rate_limit_challenge(&self) -> Result<&RateLimitChallenge, WrongErrorKind> {
        Ok(self)
    }
}

mod registration {
    use libsignal_net::infra::errors::LogSafeDisplay;
    use libsignal_net_chat::api::registration::{
        CheckSvr2CredentialsError, CreateSessionError, RegisterAccountError,
        RequestVerificationCodeError, ResumeSessionError, SubmitVerificationError,
        UpdateSessionError,
    };
    use libsignal_net_chat::registration::RequestError;

    use super::*;

    #[derive(Debug, derive_more::From)]
    enum RegistrationError<'a> {
        InvalidSessionId,
        Unexpected,
        SessionNotFound,
        NotReadyForVerification,
        SendVerificationCodeFailed,
        CodeNotDeliverable(&'a VerificationCodeNotDeliverable),
        SessionUpdateRejected,
        CredentialsCouldNotBeParsed,
        DeviceTransferPossible,
        RegistrationRecoveryVerificationFailed,
        RegistrationLock(&'a RegistrationLock),
    }

    impl<'a> From<RegistrationError<'a>> for SignalErrorCode {
        fn from(value: RegistrationError<'a>) -> Self {
            match value {
                RegistrationError::InvalidSessionId => Self::RegistrationInvalidSessionId,
                RegistrationError::Unexpected => Self::RegistrationUnknown,
                RegistrationError::SessionNotFound => Self::RegistrationSessionNotFound,
                RegistrationError::NotReadyForVerification => {
                    Self::RegistrationNotReadyForVerification
                }
                RegistrationError::SendVerificationCodeFailed => {
                    Self::RegistrationSendVerificationCodeFailed
                }
                RegistrationError::CodeNotDeliverable(_) => Self::RegistrationCodeNotDeliverable,
                RegistrationError::SessionUpdateRejected => Self::RegistrationSessionUpdateRejected,
                RegistrationError::CredentialsCouldNotBeParsed => {
                    Self::RegistrationCredentialsCouldNotBeParsed
                }
                RegistrationError::DeviceTransferPossible => {
                    Self::RegistrationDeviceTransferPossible
                }
                RegistrationError::RegistrationRecoveryVerificationFailed => {
                    Self::RegistrationRecoveryVerificationFailed
                }
                RegistrationError::RegistrationLock(_) => Self::RegistrationLock,
            }
        }
    }

    impl<E> FfiError for RequestError<E>
    where
        E: Send + LogSafeDisplay + std::fmt::Debug + 'static,
        for<'a> &'a E: Into<RegistrationError<'a>>,
    {
        fn code(&self) -> SignalErrorCode {
            let error_class = match self {
                RequestError::Timeout => return SignalErrorCode::RequestTimedOut,
                RequestError::ServerSideError | RequestError::Unexpected { log_safe: _ } => {
                    RegistrationError::Unexpected
                }
                RequestError::Other(err) => err.into(),
                RequestError::RetryLater(retry_later) => return retry_later.code(),
                RequestError::Challenge(challenge) => return challenge.code(),
                RequestError::Disconnected(d) => match *d {},
            };
            error_class.into()
        }

        fn describe(&self) -> Cow<'_, str> {
            self.to_string().into()
        }
        fn provide_retry_after_seconds(&self) -> Result<u32, WrongErrorKind> {
            match self {
                RequestError::RetryLater(retry_later) => retry_later.provide_retry_after_seconds(),
                RequestError::Other(_)
                | RequestError::Timeout
                | RequestError::Challenge(_)
                | RequestError::ServerSideError
                | RequestError::Unexpected { .. } => Err(WrongErrorKind),
                RequestError::Disconnected(d) => match *d {},
            }
        }
        fn provide_registration_code_not_deliverable(
            &self,
        ) -> Result<&VerificationCodeNotDeliverable, WrongErrorKind> {
            match self {
                RequestError::Other(e) => match e.into() {
                    RegistrationError::CodeNotDeliverable(code) => Ok(code),
                    _ => Err(WrongErrorKind),
                },
                RequestError::Timeout
                | RequestError::RetryLater(_)
                | RequestError::Challenge(_)
                | RequestError::ServerSideError
                | RequestError::Unexpected { .. } => Err(WrongErrorKind),
                RequestError::Disconnected(d) => match *d {},
            }
        }
        fn provide_registration_lock(&self) -> Result<&RegistrationLock, WrongErrorKind> {
            match self {
                RequestError::Other(e) => match e.into() {
                    RegistrationError::RegistrationLock(lock) => Ok(lock),
                    _ => Err(WrongErrorKind),
                },
                RequestError::Timeout
                | RequestError::RetryLater(_)
                | RequestError::Challenge(_)
                | RequestError::ServerSideError
                | RequestError::Unexpected { .. } => Err(WrongErrorKind),
                RequestError::Disconnected(d) => match *d {},
            }
        }
        fn provide_rate_limit_challenge(&self) -> Result<&RateLimitChallenge, WrongErrorKind> {
            match self {
                RequestError::Challenge(challenge) => Ok(challenge),
                RequestError::Other(_)
                | RequestError::Timeout
                | RequestError::RetryLater(_)
                | RequestError::ServerSideError
                | RequestError::Unexpected { .. } => Err(WrongErrorKind),
                RequestError::Disconnected(d) => match *d {},
            }
        }
    }

    impl<'a> From<&'a CreateSessionError> for RegistrationError<'a> {
        fn from(value: &'a CreateSessionError) -> Self {
            match value {
                CreateSessionError::InvalidSessionId => Self::InvalidSessionId,
            }
        }
    }

    impl<'a> From<&'a ResumeSessionError> for RegistrationError<'a> {
        fn from(value: &'a ResumeSessionError) -> Self {
            match value {
                ResumeSessionError::InvalidSessionId => Self::InvalidSessionId,
                ResumeSessionError::SessionNotFound => Self::SessionNotFound,
            }
        }
    }

    impl<'a> From<&'a RequestVerificationCodeError> for RegistrationError<'a> {
        fn from(value: &'a RequestVerificationCodeError) -> Self {
            match value {
                RequestVerificationCodeError::InvalidSessionId => Self::InvalidSessionId,
                RequestVerificationCodeError::SessionNotFound => Self::SessionNotFound,
                RequestVerificationCodeError::NotReadyForVerification => {
                    Self::NotReadyForVerification
                }
                RequestVerificationCodeError::SendFailed => Self::SendVerificationCodeFailed,
                RequestVerificationCodeError::CodeNotDeliverable(not_deliverable) => {
                    Self::CodeNotDeliverable(not_deliverable)
                }
            }
        }
    }

    impl<'a> From<&'a UpdateSessionError> for RegistrationError<'a> {
        fn from(value: &'a UpdateSessionError) -> Self {
            match value {
                UpdateSessionError::Rejected => Self::SessionUpdateRejected,
            }
        }
    }

    impl<'a> From<&'a SubmitVerificationError> for RegistrationError<'a> {
        fn from(value: &'a SubmitVerificationError) -> Self {
            match value {
                SubmitVerificationError::InvalidSessionId => Self::InvalidSessionId,
                SubmitVerificationError::SessionNotFound => Self::SessionNotFound,
                SubmitVerificationError::NotReadyForVerification => Self::NotReadyForVerification,
            }
        }
    }

    impl<'a> From<&'a CheckSvr2CredentialsError> for RegistrationError<'a> {
        fn from(value: &'a CheckSvr2CredentialsError) -> Self {
            match value {
                CheckSvr2CredentialsError::CredentialsCouldNotBeParsed => {
                    Self::CredentialsCouldNotBeParsed
                }
            }
        }
    }

    impl<'a> From<&'a RegisterAccountError> for RegistrationError<'a> {
        fn from(value: &'a RegisterAccountError) -> Self {
            match value {
                RegisterAccountError::DeviceTransferIsPossibleButNotSkipped => {
                    Self::DeviceTransferPossible
                }
                RegisterAccountError::RegistrationRecoveryVerificationFailed => {
                    Self::RegistrationRecoveryVerificationFailed
                }
                RegisterAccountError::RegistrationLock(registration_lock) => {
                    Self::RegistrationLock(registration_lock)
                }
            }
        }
    }
}

impl IntoFfiError for http::uri::InvalidUri {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        SimpleError::new(
            SignalErrorCode::InvalidArgument,
            format!("invalid argument: {self}"),
        )
    }
}

#[cfg(feature = "signal-media")]
impl IntoFfiError for signal_media::sanitize::mp4::Error {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        match self {
            Self::Io(e) => e.into_ffi_error().into(),
            Self::Parse(e) => {
                use signal_media::sanitize::mp4::ParseError;
                let code = match e.kind {
                    ParseError::InvalidBoxLayout
                    | ParseError::InvalidInput
                    | ParseError::MissingRequiredBox { .. }
                    | ParseError::TruncatedBox => SignalErrorCode::InvalidMediaInput,

                    ParseError::UnsupportedBoxLayout
                    | ParseError::UnsupportedBox { .. }
                    | ParseError::UnsupportedFormat { .. } => {
                        SignalErrorCode::UnsupportedMediaInput
                    }
                };
                SimpleError::new(code, format!("Mp4 sanitizer failed to parse mp4 file: {e}"))
                    .into()
            }
        }
    }
}

#[cfg(feature = "signal-media")]
impl IntoFfiError for signal_media::sanitize::webp::Error {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        match self {
            Self::Io(e) => e.into_ffi_error().into(),
            Self::Parse(e) => {
                use signal_media::sanitize::webp::ParseError;
                let code = match e.kind {
                    ParseError::InvalidChunkLayout
                    | ParseError::InvalidInput
                    | ParseError::InvalidVp8lPrefixCode
                    | ParseError::MissingRequiredChunk { .. }
                    | ParseError::TruncatedChunk => SignalErrorCode::InvalidMediaInput,

                    ParseError::UnsupportedChunk { .. }
                    | ParseError::UnsupportedVp8lVersion { .. } => {
                        SignalErrorCode::UnsupportedMediaInput
                    }
                };
                SimpleError::new(
                    code,
                    format!("WebP sanitizer failed to parse webp file: {e}"),
                )
                .into()
            }
        }
    }
}

impl FfiError for libsignal_message_backup::ReadError {
    fn describe(&self) -> Cow<'_, str> {
        self.to_string().into()
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

impl IntoFfiError for NullPointerError {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        SimpleError::new(SignalErrorCode::NullParameter, "null pointer")
    }
}

impl IntoFfiError for UnexpectedPanic {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        SimpleError::new(
            SignalErrorCode::InternalError,
            format!("unexpected panic: {}", describe_panic(&self.0)),
        )
    }
}

impl IntoFfiError for std::str::Utf8Error {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        SimpleError::new(SignalErrorCode::InvalidUtf8String, "invalid UTF8 string")
    }
}

impl IntoFfiError for FutureCancelled {
    fn into_ffi_error(self) -> impl Into<SignalFfiError> {
        SimpleError::new(SignalErrorCode::Cancelled, "cancelled")
    }
}

impl FfiError for libsignal_net::svrb::Error {
    fn describe(&self) -> Cow<'_, str> {
        use libsignal_net::infra::ws::WebSocketConnectError;

        match self {
            Self::AllConnectionAttemptsFailed => {
                "no connection attempts succeeded before timeout".into()
            }
            Self::Connect(e) => match e {
                WebSocketConnectError::Transport(e) => format!("IO error: {e}").into(),
                WebSocketConnectError::WebSocketError(e) => format!("WebSocket error: {e}").into(),
            },
            Self::RateLimited(inner) => inner.describe(),
            Self::Service(e) => format!("WebSocket error: {e}").into(),
            Self::Protocol(e) => format!("Protocol error: {e}").into(),
            Self::AttestationError(inner) => inner.describe(),
            Self::RestoreFailed(_)
            | Self::DataMissing
            | Self::PreviousBackupDataInvalid
            | Self::MetadataInvalid
            | Self::DecryptionError(_) => format!("SVR error: {self}").into(),
        }
    }

    fn code(&self) -> SignalErrorCode {
        use libsignal_net::infra::ws::WebSocketConnectError;

        match self {
            Self::AllConnectionAttemptsFailed => SignalErrorCode::ConnectionFailed,
            Self::Connect(e) => match e {
                WebSocketConnectError::Transport(_) => SignalErrorCode::IoError,
                WebSocketConnectError::WebSocketError(_) => SignalErrorCode::WebSocket,
            },
            Self::RateLimited(inner) => inner.code(),
            Self::Service(_) => SignalErrorCode::WebSocket,
            Self::AttestationError(inner) => inner.code(),
            Self::Protocol(_) => SignalErrorCode::NetworkProtocol,
            Self::RestoreFailed(_) => SignalErrorCode::SvrRestoreFailed,
            Self::DataMissing => SignalErrorCode::SvrDataMissing,
            Self::PreviousBackupDataInvalid => SignalErrorCode::InvalidArgument,
            Self::MetadataInvalid => SignalErrorCode::InvalidArgument,
            Self::DecryptionError(_) => SignalErrorCode::InvalidArgument,
        }
    }

    fn provide_tries_remaining(&self) -> Result<u32, WrongErrorKind> {
        match self {
            Self::RestoreFailed(tries) => Ok(*tries),
            _ => Err(WrongErrorKind),
        }
    }

    fn provide_retry_after_seconds(&self) -> Result<u32, WrongErrorKind> {
        match self {
            Self::RateLimited(inner) => inner.provide_retry_after_seconds(),
            _ => Err(WrongErrorKind),
        }
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
