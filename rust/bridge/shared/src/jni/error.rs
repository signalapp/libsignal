//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use http::uri::InvalidUri;
use std::fmt;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::time::Duration;

use jni::objects::{GlobalRef, JObject, JString, JThrowable};
use jni::{JNIEnv, JavaVM};

use attest::hsm_enclave::Error as HsmEnclaveError;
use device_transfer::Error as DeviceTransferError;
use libsignal_net::chat::ChatServiceError;
use libsignal_net::infra::ws::{WebSocketConnectError, WebSocketServiceError};
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use signal_pin::Error as PinError;
use usernames::{UsernameError, UsernameLinkError};
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use crate::net::cdsi::CdsiError;
use crate::support::describe_panic;

use super::*;

/// The top-level error type for when something goes wrong.
#[derive(Debug, thiserror::Error)]
pub enum SignalJniError {
    Protocol(SignalProtocolError),
    DeviceTransfer(DeviceTransferError),
    SignalCrypto(SignalCryptoError),
    HsmEnclave(HsmEnclaveError),
    Enclave(EnclaveError),
    Pin(PinError),
    ZkGroupDeserializationFailure(ZkGroupDeserializationFailure),
    ZkGroupVerificationFailure(ZkGroupVerificationFailure),
    UsernameError(UsernameError),
    UsernameProofError(usernames::ProofVerificationFailure),
    UsernameLinkError(UsernameLinkError),
    Io(IoError),
    #[cfg(feature = "signal-media")]
    Mp4SanitizeParse(signal_media::sanitize::mp4::ParseErrorReport),
    #[cfg(feature = "signal-media")]
    WebpSanitizeParse(signal_media::sanitize::webp::ParseErrorReport),
    Cdsi(CdsiError),
    Svr3(libsignal_net::svr3::Error),
    WebSocket(#[from] WebSocketServiceError),
    ChatService(ChatServiceError),
    InvalidUri(InvalidUri),
    ConnectTimedOut,
    Bridge(BridgeLayerError),
    #[cfg(feature = "testing-fns")]
    TestingError {
        exception_class: &'static str,
    },
}

/// Subset of errors that can happen in the bridge layer.
///
/// These errors will always be converted to RuntimeExceptions or Errors, i.e. unchecked throwables,
/// except for the [`Self::CallbackException`] case, which is rethrown.
#[derive(Debug)]
pub enum BridgeLayerError {
    Jni(jni::errors::Error),
    BadArgument(String),
    BadJniParameter(&'static str),
    UnexpectedJniResultType(&'static str, &'static str),
    NullPointer(Option<&'static str>),
    IntegerOverflow(String),
    IncorrectArrayLength { expected: usize, actual: usize },
    CallbackException(&'static str, ThrownException),
    UnexpectedPanic(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
}

impl fmt::Display for SignalJniError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignalJniError::Protocol(s) => write!(f, "{}", s),
            SignalJniError::DeviceTransfer(s) => write!(f, "{}", s),
            SignalJniError::HsmEnclave(e) => write!(f, "{}", e),
            SignalJniError::Enclave(e) => write!(f, "{}", e),
            SignalJniError::Pin(e) => write!(f, "{}", e),
            SignalJniError::SignalCrypto(s) => write!(f, "{}", s),
            SignalJniError::ZkGroupVerificationFailure(e) => write!(f, "{}", e),
            SignalJniError::ZkGroupDeserializationFailure(e) => write!(f, "{}", e),
            SignalJniError::UsernameError(e) => write!(f, "{}", e),
            SignalJniError::UsernameProofError(e) => write!(f, "{}", e),
            SignalJniError::UsernameLinkError(e) => write!(f, "{}", e),
            SignalJniError::Io(e) => write!(f, "{}", e),
            #[cfg(feature = "signal-media")]
            SignalJniError::Mp4SanitizeParse(e) => write!(f, "{}", e),
            #[cfg(feature = "signal-media")]
            SignalJniError::WebpSanitizeParse(e) => write!(f, "{}", e),
            SignalJniError::Cdsi(e) => write!(f, "{}", e),
            SignalJniError::ChatService(e) => write!(f, "{}", e),
            SignalJniError::InvalidUri(e) => write!(f, "{}", e),
            SignalJniError::WebSocket(e) => write!(f, "{e}"),
            SignalJniError::ConnectTimedOut => write!(f, "connect timed out"),
            SignalJniError::Svr3(e) => write!(f, "{}", e),
            SignalJniError::Bridge(e) => write!(f, "{}", e),
            #[cfg(feature = "testing-fns")]
            SignalJniError::TestingError { exception_class } => {
                write!(f, "TestingError({})", exception_class)
            }
        }
    }
}

impl fmt::Display for BridgeLayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jni(s) => write!(f, "JNI error {}", s),
            Self::NullPointer(None) => write!(f, "unexpected null"),
            Self::NullPointer(Some(expected_type)) => {
                write!(f, "got null where {expected_type} instance is expected")
            }
            Self::BadArgument(m) => write!(f, "{}", m),
            Self::BadJniParameter(m) => write!(f, "bad parameter type {}", m),
            Self::UnexpectedJniResultType(m, t) => {
                write!(f, "calling {} returned unexpected type {}", m, t)
            }
            Self::IntegerOverflow(m) => {
                write!(f, "integer overflow during conversion of {}", m)
            }
            Self::IncorrectArrayLength { expected, actual } => {
                write!(
                    f,
                    "expected array with length {} (was {})",
                    expected, actual
                )
            }
            Self::CallbackException(callback_name, exception) => {
                write!(f, "exception in method call '{callback_name}': {exception}")
            }
            Self::UnexpectedPanic(e) => {
                write!(f, "unexpected panic: {}", describe_panic(e))
            }
        }
    }
}

impl From<SignalProtocolError> for SignalJniError {
    fn from(e: SignalProtocolError) -> SignalJniError {
        SignalJniError::Protocol(e)
    }
}

impl From<DeviceTransferError> for SignalJniError {
    fn from(e: DeviceTransferError) -> SignalJniError {
        SignalJniError::DeviceTransfer(e)
    }
}

impl From<HsmEnclaveError> for SignalJniError {
    fn from(e: HsmEnclaveError) -> SignalJniError {
        SignalJniError::HsmEnclave(e)
    }
}

impl From<EnclaveError> for SignalJniError {
    fn from(e: EnclaveError) -> SignalJniError {
        SignalJniError::Enclave(e)
    }
}

impl From<PinError> for SignalJniError {
    fn from(e: PinError) -> SignalJniError {
        SignalJniError::Pin(e)
    }
}

impl From<SignalCryptoError> for SignalJniError {
    fn from(e: SignalCryptoError) -> SignalJniError {
        SignalJniError::SignalCrypto(e)
    }
}

impl From<ZkGroupVerificationFailure> for SignalJniError {
    fn from(e: ZkGroupVerificationFailure) -> SignalJniError {
        SignalJniError::ZkGroupVerificationFailure(e)
    }
}

impl From<ZkGroupDeserializationFailure> for SignalJniError {
    fn from(e: ZkGroupDeserializationFailure) -> SignalJniError {
        SignalJniError::ZkGroupDeserializationFailure(e)
    }
}

impl From<UsernameError> for SignalJniError {
    fn from(e: UsernameError) -> Self {
        SignalJniError::UsernameError(e)
    }
}

impl From<usernames::ProofVerificationFailure> for SignalJniError {
    fn from(e: usernames::ProofVerificationFailure) -> Self {
        SignalJniError::UsernameProofError(e)
    }
}

impl From<UsernameLinkError> for SignalJniError {
    fn from(e: UsernameLinkError) -> Self {
        SignalJniError::UsernameLinkError(e)
    }
}

impl From<InvalidUri> for SignalJniError {
    fn from(e: InvalidUri) -> Self {
        SignalJniError::InvalidUri(e)
    }
}

impl From<ChatServiceError> for SignalJniError {
    fn from(e: ChatServiceError) -> Self {
        SignalJniError::ChatService(e)
    }
}

impl From<IoError> for SignalJniError {
    fn from(e: IoError) -> SignalJniError {
        Self::Io(e)
    }
}

#[cfg(feature = "signal-media")]
impl From<signal_media::sanitize::mp4::Error> for SignalJniError {
    fn from(e: signal_media::sanitize::mp4::Error) -> Self {
        use signal_media::sanitize::mp4::Error;
        match e {
            Error::Io(e) => Self::Io(e),
            Error::Parse(e) => Self::Mp4SanitizeParse(e),
        }
    }
}

#[cfg(feature = "signal-media")]
impl From<signal_media::sanitize::webp::Error> for SignalJniError {
    fn from(e: signal_media::sanitize::webp::Error) -> Self {
        use signal_media::sanitize::webp::Error;
        match e {
            Error::Io(e) => Self::Io(e),
            Error::Parse(e) => Self::WebpSanitizeParse(e),
        }
    }
}

impl From<libsignal_net::cdsi::LookupError> for SignalJniError {
    fn from(e: libsignal_net::cdsi::LookupError) -> SignalJniError {
        use libsignal_net::cdsi::LookupError;
        SignalJniError::Cdsi(match e {
            LookupError::ConnectionTimedOut => return SignalJniError::ConnectTimedOut,
            LookupError::AttestationError(e) => return e.into(),
            LookupError::ConnectTransport(e) => return IoError::from(e).into(),
            LookupError::WebSocket(e) => return e.into(),
            LookupError::InvalidArgument { server_reason: _ } => {
                return SignalJniError::Protocol(SignalProtocolError::InvalidArgument(
                    e.to_string(),
                ))
            }
            LookupError::InvalidResponse => CdsiError::InvalidResponse,
            LookupError::Protocol => CdsiError::Protocol,
            LookupError::RateLimited {
                retry_after_seconds,
            } => CdsiError::RateLimited {
                retry_after: Duration::from_secs(retry_after_seconds.into()),
            },
            LookupError::ParseError => CdsiError::ParseError,
            LookupError::InvalidToken => CdsiError::InvalidToken,
            LookupError::Server { reason } => CdsiError::Server { reason },
        })
    }
}

impl From<BridgeLayerError> for SignalJniError {
    fn from(e: BridgeLayerError) -> SignalJniError {
        SignalJniError::Bridge(e)
    }
}

impl From<jni::errors::Error> for BridgeLayerError {
    fn from(e: jni::errors::Error) -> BridgeLayerError {
        BridgeLayerError::Jni(e)
    }
}

impl From<Svr3Error> for SignalJniError {
    fn from(err: Svr3Error) -> Self {
        match err {
            Svr3Error::Connect(inner) => match inner {
                WebSocketConnectError::Timeout => SignalJniError::ConnectTimedOut,
                WebSocketConnectError::Transport(e) => SignalJniError::Io(e.into()),
                WebSocketConnectError::WebSocketError(e) => WebSocketServiceError::from(e).into(),
            },
            Svr3Error::ConnectionTimedOut => SignalJniError::ConnectTimedOut,
            Svr3Error::Service(inner) => inner.into(),
            Svr3Error::AttestationError(inner) => inner.into(),
            Svr3Error::Protocol(_)
            | Svr3Error::RequestFailed(_)
            | Svr3Error::RestoreFailed
            | Svr3Error::DataMissing => SignalJniError::Svr3(err),
        }
    }
}

impl From<jni::errors::Error> for SignalJniError {
    fn from(e: jni::errors::Error) -> SignalJniError {
        BridgeLayerError::from(e).into()
    }
}

impl From<SignalJniError> for SignalProtocolError {
    fn from(err: SignalJniError) -> SignalProtocolError {
        match err {
            SignalJniError::Protocol(e) => e,
            SignalJniError::Bridge(BridgeLayerError::BadJniParameter(m)) => {
                SignalProtocolError::InvalidArgument(m.to_string())
            }
            SignalJniError::Bridge(BridgeLayerError::CallbackException(callback, exception)) => {
                SignalProtocolError::ApplicationCallbackError(callback, Box::new(exception))
            }
            _ => SignalProtocolError::FfiBindingError(format!("{}", err)),
        }
    }
}

impl From<SignalJniError> for IoError {
    fn from(err: SignalJniError) -> Self {
        match err {
            SignalJniError::Io(e) => e,
            SignalJniError::Bridge(BridgeLayerError::CallbackException(
                _method_name,
                exception,
            )) => IoError::new(IoErrorKind::Other, exception),
            e => IoError::new(IoErrorKind::Other, e.to_string()),
        }
    }
}

pub type SignalJniResult<T> = Result<T, SignalJniError>;

/// A lifetime-less reference to a thrown Java exception that can be used as an [`Error`].
///
/// `ThrownException` allows a Java exception to be safely persisted past the lifetime of a
/// particular call.
///
/// Ideally, `ThrownException` should be Dropped on the thread the JVM is running on; see
/// [`jni::objects::GlobalRef`] for more details.
pub struct ThrownException {
    // GlobalRef already carries a JavaVM reference, but it's not accessible to us.
    jvm: JavaVM,
    exception_ref: GlobalRef,
}

impl ThrownException {
    /// Gets the wrapped exception as a live object with a lifetime.
    pub fn as_obj(&self) -> &JThrowable<'static> {
        self.exception_ref.as_obj().into()
    }

    /// Persists the given throwable.
    pub fn new<'a>(env: &JNIEnv<'a>, throwable: JThrowable<'a>) -> Result<Self, BridgeLayerError> {
        assert!(**throwable != *JObject::null());
        Ok(Self {
            jvm: env.get_java_vm()?,
            exception_ref: env.new_global_ref(throwable)?,
        })
    }

    pub fn class_name(&self, env: &mut JNIEnv) -> Result<String, BridgeLayerError> {
        let class_type = env.get_object_class(self.exception_ref.as_obj())?;
        let class_name: JObject = call_method_checked(
            env,
            class_type,
            "getCanonicalName",
            jni_args!(() -> java.lang.String),
        )?;

        Ok(env.get_string(&JString::from(class_name))?.into())
    }

    pub fn message(&self, env: &mut JNIEnv) -> Result<String, BridgeLayerError> {
        let message: JObject = call_method_checked(
            env,
            self.exception_ref.as_obj(),
            "getMessage",
            jni_args!(() -> java.lang.String),
        )?;
        Ok(env.get_string(&JString::from(message))?.into())
    }
}

impl fmt::Display for ThrownException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let env = &mut self.jvm.attach_current_thread().map_err(|_| fmt::Error)?;

        let exn_type = self.class_name(env);
        let exn_type = exn_type.as_deref().unwrap_or("<unknown>");

        if let Ok(message) = self.message(env) {
            write!(f, "exception {} \"{}\"", exn_type, message)
        } else {
            write!(f, "exception {}", exn_type)
        }
    }
}

impl fmt::Debug for ThrownException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let env = &mut self.jvm.attach_current_thread().map_err(|_| fmt::Error)?;

        let exn_type = self.class_name(env);
        let exn_type = exn_type.as_deref().unwrap_or("<unknown>");

        let obj_addr = **self.exception_ref.as_obj();

        if let Ok(message) = self.message(env) {
            write!(f, "exception {} ({:p}) \"{}\"", exn_type, obj_addr, message)
        } else {
            write!(f, "exception {} ({:p})", exn_type, obj_addr)
        }
    }
}

impl std::error::Error for ThrownException {}
