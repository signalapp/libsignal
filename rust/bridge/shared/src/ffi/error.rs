//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use attest::enclave::Error as EnclaveError;
use attest::hsm_enclave::Error as HsmEnclaveError;
use device_transfer::Error as DeviceTransferError;
use libsignal_net::chat::ChatServiceError;
use libsignal_net::infra::ws::{WebSocketConnectError, WebSocketServiceError};
use libsignal_net::svr3::Error as Svr3Error;
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use signal_pin::Error as PinError;
use usernames::{UsernameError, UsernameLinkError};
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use crate::support::describe_panic;

use super::NullPointerError;

/// The top-level error type (opaquely) returned to C clients when something goes wrong.
#[derive(Debug, thiserror::Error)]
pub enum SignalFfiError {
    Signal(SignalProtocolError),
    DeviceTransfer(DeviceTransferError),
    HsmEnclave(HsmEnclaveError),
    Sgx(EnclaveError),
    Pin(PinError),
    SignalCrypto(SignalCryptoError),
    ZkGroupVerificationFailure(ZkGroupVerificationFailure),
    ZkGroupDeserializationFailure(ZkGroupDeserializationFailure),
    UsernameError(UsernameError),
    UsernameProofError(usernames::ProofVerificationFailure),
    UsernameLinkError(UsernameLinkError),
    Io(IoError),
    WebSocket(#[from] WebSocketServiceError),
    ConnectionTimedOut,
    ConnectionFailed,
    ChatServiceInactive,
    NetworkProtocol(String),
    CdsiInvalidToken,
    RateLimited {
        retry_after_seconds: u32,
    },
    Svr(Svr3Error),
    #[cfg(feature = "signal-media")]
    Mp4SanitizeParse(signal_media::sanitize::mp4::ParseErrorReport),
    #[cfg(feature = "signal-media")]
    WebpSanitizeParse(signal_media::sanitize::webp::ParseErrorReport),
    NullPointer,
    InvalidUtf8String,
    InvalidArgument(String),
    InternalError(String),
    UnexpectedPanic(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
}

impl fmt::Display for SignalFfiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignalFfiError::Signal(s) => write!(f, "{}", s),
            SignalFfiError::DeviceTransfer(c) => {
                write!(f, "Device transfer operation failed: {}", c)
            }
            SignalFfiError::HsmEnclave(e) => {
                write!(f, "HSM enclave operation failed: {}", e)
            }
            SignalFfiError::Sgx(e) => {
                write!(f, "SGX operation failed: {}", e)
            }
            SignalFfiError::SignalCrypto(c) => {
                write!(f, "Cryptographic operation failed: {}", c)
            }
            SignalFfiError::Pin(e) => write!(f, "{}", e),
            SignalFfiError::ZkGroupVerificationFailure(e) => write!(f, "{}", e),
            SignalFfiError::ZkGroupDeserializationFailure(e) => write!(f, "{}", e),
            SignalFfiError::UsernameError(e) => write!(f, "{}", e),
            SignalFfiError::UsernameProofError(e) => write!(f, "{}", e),
            SignalFfiError::UsernameLinkError(e) => write!(f, "{}", e),
            SignalFfiError::Io(e) => write!(f, "IO error: {}", e),
            SignalFfiError::ConnectionTimedOut => write!(f, "Connect timed out"),
            SignalFfiError::ConnectionFailed => write!(f, "Connection failed"),
            SignalFfiError::ChatServiceInactive => write!(f, "Chat service inactive"),
            SignalFfiError::WebSocket(e) => write!(f, "WebSocket error: {e}"),
            SignalFfiError::CdsiInvalidToken => write!(f, "CDSI request token was invalid"),
            SignalFfiError::NetworkProtocol(message) => write!(f, "Protocol error: {}", message),
            SignalFfiError::RateLimited {
                retry_after_seconds,
            } => write!(f, "Rate limited; try again after {}s", retry_after_seconds),
            SignalFfiError::Svr(e) => write!(f, "SVR error: {e}"),
            #[cfg(feature = "signal-media")]
            SignalFfiError::Mp4SanitizeParse(e) => {
                write!(f, "Mp4 sanitizer failed to parse mp4 file: {}", e)
            }
            #[cfg(feature = "signal-media")]
            SignalFfiError::WebpSanitizeParse(e) => {
                write!(f, "WebP sanitizer failed to parse webp file: {}", e)
            }
            SignalFfiError::NullPointer => write!(f, "null pointer"),
            SignalFfiError::InvalidUtf8String => write!(f, "invalid UTF8 string"),
            SignalFfiError::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            SignalFfiError::InternalError(msg) => write!(f, "internal error: {msg}"),
            SignalFfiError::UnexpectedPanic(e) => {
                write!(f, "unexpected panic: {}", describe_panic(e))
            }
        }
    }
}

impl From<SignalProtocolError> for SignalFfiError {
    fn from(e: SignalProtocolError) -> SignalFfiError {
        SignalFfiError::Signal(e)
    }
}

impl From<DeviceTransferError> for SignalFfiError {
    fn from(e: DeviceTransferError) -> SignalFfiError {
        SignalFfiError::DeviceTransfer(e)
    }
}

impl From<HsmEnclaveError> for SignalFfiError {
    fn from(e: HsmEnclaveError) -> SignalFfiError {
        SignalFfiError::HsmEnclave(e)
    }
}

impl From<EnclaveError> for SignalFfiError {
    fn from(e: EnclaveError) -> SignalFfiError {
        SignalFfiError::Sgx(e)
    }
}

impl From<PinError> for SignalFfiError {
    fn from(e: PinError) -> SignalFfiError {
        SignalFfiError::Pin(e)
    }
}

impl From<SignalCryptoError> for SignalFfiError {
    fn from(e: SignalCryptoError) -> SignalFfiError {
        SignalFfiError::SignalCrypto(e)
    }
}

impl From<ZkGroupVerificationFailure> for SignalFfiError {
    fn from(e: ZkGroupVerificationFailure) -> SignalFfiError {
        SignalFfiError::ZkGroupVerificationFailure(e)
    }
}

impl From<ZkGroupDeserializationFailure> for SignalFfiError {
    fn from(e: ZkGroupDeserializationFailure) -> SignalFfiError {
        SignalFfiError::ZkGroupDeserializationFailure(e)
    }
}

impl From<UsernameError> for SignalFfiError {
    fn from(e: UsernameError) -> SignalFfiError {
        SignalFfiError::UsernameError(e)
    }
}

impl From<usernames::ProofVerificationFailure> for SignalFfiError {
    fn from(e: usernames::ProofVerificationFailure) -> SignalFfiError {
        SignalFfiError::UsernameProofError(e)
    }
}

impl From<UsernameLinkError> for SignalFfiError {
    fn from(e: UsernameLinkError) -> SignalFfiError {
        SignalFfiError::UsernameLinkError(e)
    }
}

impl From<IoError> for SignalFfiError {
    fn from(mut e: IoError) -> SignalFfiError {
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

        if let Some(callback_err) = original_error {
            Self::Signal(callback_err)
        } else {
            Self::Io(e)
        }
    }
}

impl From<libsignal_net::cdsi::LookupError> for SignalFfiError {
    fn from(value: libsignal_net::cdsi::LookupError) -> Self {
        use libsignal_net::cdsi::LookupError;

        match value {
            LookupError::AttestationError(e) => SignalFfiError::Sgx(e),
            LookupError::ConnectTransport(e) => SignalFfiError::Io(e.into()),
            LookupError::WebSocket(e) => SignalFfiError::WebSocket(e),
            LookupError::ConnectionTimedOut => SignalFfiError::ConnectionTimedOut,
            LookupError::ParseError
            | LookupError::Protocol
            | LookupError::InvalidResponse
            | LookupError::Server { reason: _ } => {
                SignalFfiError::NetworkProtocol(value.to_string())
            }
            LookupError::RateLimited {
                retry_after_seconds: retry_after,
            } => SignalFfiError::RateLimited {
                retry_after_seconds: retry_after,
            },
            LookupError::InvalidToken => SignalFfiError::CdsiInvalidToken,
            LookupError::InvalidArgument { server_reason: _ } => {
                SignalFfiError::Signal(SignalProtocolError::InvalidArgument(value.to_string()))
            }
        }
    }
}

impl From<Svr3Error> for SignalFfiError {
    fn from(err: Svr3Error) -> Self {
        match err {
            Svr3Error::Connect(e) => match e {
                WebSocketConnectError::Transport(e) => SignalFfiError::Io(e.into()),
                WebSocketConnectError::Timeout => SignalFfiError::ConnectionTimedOut,
                WebSocketConnectError::WebSocketError(e) => WebSocketServiceError::from(e).into(),
            },
            Svr3Error::Service(e) => SignalFfiError::WebSocket(e),
            Svr3Error::ConnectionTimedOut => SignalFfiError::ConnectionTimedOut,
            Svr3Error::AttestationError(inner) => SignalFfiError::Sgx(inner),
            Svr3Error::Protocol(inner) => SignalFfiError::NetworkProtocol(inner.to_string()),
            Svr3Error::RequestFailed(_) | Svr3Error::RestoreFailed | Svr3Error::DataMissing => {
                SignalFfiError::Svr(err)
            }
        }
    }
}

impl From<ChatServiceError> for SignalFfiError {
    fn from(err: ChatServiceError) -> Self {
        match err {
            ChatServiceError::WebSocket(e) => SignalFfiError::WebSocket(e),
            ChatServiceError::AllConnectionRoutesFailed { attempts: _ }
            | ChatServiceError::ServiceUnavailable => SignalFfiError::ConnectionFailed,
            ChatServiceError::UnexpectedFrameReceived
            | ChatServiceError::ServerRequestMissingId
            | ChatServiceError::IncomingDataInvalid => {
                SignalFfiError::NetworkProtocol(err.to_string())
            }
            ChatServiceError::FailedToPassMessageToIncomingChannel => {
                SignalFfiError::InternalError(err.to_string())
            }
            ChatServiceError::RequestHasInvalidHeader => SignalFfiError::InternalError(format!(
                "{err} (but libsignal_ffi only supports string values anyway, so how?)"
            )),
            ChatServiceError::Timeout
            | ChatServiceError::TimeoutEstablishingConnection { attempts: _ } => {
                SignalFfiError::ConnectionTimedOut
            }
            ChatServiceError::ServiceInactive => SignalFfiError::ChatServiceInactive,
        }
    }
}

impl From<http::uri::InvalidUri> for SignalFfiError {
    fn from(err: http::uri::InvalidUri) -> Self {
        SignalFfiError::InvalidArgument(err.to_string())
    }
}

#[cfg(feature = "signal-media")]
impl From<signal_media::sanitize::mp4::Error> for SignalFfiError {
    fn from(e: signal_media::sanitize::mp4::Error) -> SignalFfiError {
        use signal_media::sanitize::mp4::Error;
        match e {
            Error::Io(e) => Self::Io(e),
            Error::Parse(e) => Self::Mp4SanitizeParse(e),
        }
    }
}

#[cfg(feature = "signal-media")]
impl From<signal_media::sanitize::webp::Error> for SignalFfiError {
    fn from(e: signal_media::sanitize::webp::Error) -> SignalFfiError {
        use signal_media::sanitize::webp::Error;
        match e {
            Error::Io(e) => Self::Io(e),
            Error::Parse(e) => Self::WebpSanitizeParse(e),
        }
    }
}

impl From<NullPointerError> for SignalFfiError {
    fn from(_: NullPointerError) -> SignalFfiError {
        SignalFfiError::NullPointer
    }
}

impl From<SignalFfiError> for IoError {
    fn from(e: SignalFfiError) -> Self {
        match e {
            SignalFfiError::Io(e) => e,
            e => IoError::new(IoErrorKind::Other, e.to_string()),
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
