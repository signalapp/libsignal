//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::fmt;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::time::Duration;

use attest::hsm_enclave::Error as HsmEnclaveError;
use device_transfer::Error as DeviceTransferError;
use http::uri::InvalidUri;
use jni::objects::{GlobalRef, JObject, JString, JThrowable};
use jni::{JNIEnv, JavaVM};
use libsignal_account_keys::Error as PinError;
use libsignal_net::cdsi::CdsiProtocolError;
use libsignal_net::chat::ChatServiceError;
use libsignal_net::infra::ws::{WebSocketConnectError, WebSocketServiceError};
use libsignal_net::ws::WebSocketServiceConnectError;
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use usernames::{UsernameError, UsernameLinkError};
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use super::*;
use crate::net::cdsi::CdsiError;
use crate::support::describe_panic;

/// The top-level error type for when something goes wrong.
#[derive(Debug, thiserror::Error, derive_more::From)]
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
    #[from(skip)]
    Svr3(libsignal_net::svr3::Error),
    WebSocket(WebSocketServiceError),
    ChatService(ChatServiceError),
    InvalidUri(InvalidUri),
    ConnectTimedOut,
    BackupValidation(libsignal_message_backup::ReadError),
    Bridge(BridgeLayerError),
    #[from(skip)]
    TestingError {
        exception_class: ClassName<'static>,
    },
    #[from(skip)]
    KeyTransparency(libsignal_net::keytrans::Error),
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
            SignalJniError::BackupValidation(e) => write!(f, "{}", e),
            SignalJniError::Svr3(e) => write!(f, "{}", e),
            SignalJniError::Bridge(e) => write!(f, "{}", e),
            SignalJniError::TestingError { exception_class } => {
                write!(f, "TestingError({})", exception_class)
            }
            SignalJniError::KeyTransparency(e) => write!(f, "{}", e),
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
            LookupError::EnclaveProtocol(_) => CdsiError::Protocol,
            LookupError::CdsiProtocol(CdsiProtocolError::NoTokenInResponse) => {
                CdsiError::NoTokenInResponse
            }
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

impl From<Svr3Error> for SignalJniError {
    fn from(err: Svr3Error) -> Self {
        match err {
            Svr3Error::Connect(inner) => match inner {
                WebSocketServiceConnectError::Connect(e, _) => match e {
                    WebSocketConnectError::Timeout => SignalJniError::ConnectTimedOut,
                    WebSocketConnectError::Transport(e) => SignalJniError::Io(e.into()),
                    WebSocketConnectError::WebSocketError(e) => {
                        WebSocketServiceError::from(e).into()
                    }
                },
                WebSocketServiceConnectError::RejectedByServer {
                    response,
                    received_at: _,
                } => WebSocketServiceError::Http(response).into(),
            },
            Svr3Error::ConnectionTimedOut => SignalJniError::ConnectTimedOut,
            Svr3Error::Service(inner) => inner.into(),
            Svr3Error::AttestationError(inner) => inner.into(),
            Svr3Error::Protocol(_)
            | Svr3Error::RequestFailed(_)
            | Svr3Error::RestoreFailed(_)
            | Svr3Error::DataMissing
            | Svr3Error::RotationMachineTooManySteps => SignalJniError::Svr3(err),
        }
    }
}

impl From<KeyTransNetError> for SignalJniError {
    fn from(err: KeyTransNetError) -> Self {
        match err {
            KeyTransNetError::ChatServiceError(e) => SignalJniError::ChatService(e),
            KeyTransNetError::RequestFailed(_)
            | KeyTransNetError::VerificationFailed(_)
            | KeyTransNetError::InvalidResponse(_)
            | KeyTransNetError::InvalidRequest(_)
            | KeyTransNetError::DecodingFailed(_) => SignalJniError::KeyTransparency(err),
        }
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
    pub fn new<'a>(
        env: &JNIEnv<'a>,
        throwable: impl AsRef<JThrowable<'a>>,
    ) -> Result<Self, BridgeLayerError> {
        assert!(!throwable.as_ref().is_null());
        Ok(Self {
            jvm: env.get_java_vm().expect_no_exceptions()?,
            exception_ref: env
                .new_global_ref(throwable.as_ref())
                .expect_no_exceptions()?,
        })
    }

    pub fn class_name(&self, env: &mut JNIEnv) -> Result<String, BridgeLayerError> {
        let class_type = env
            .get_object_class(self.exception_ref.as_obj())
            .check_exceptions(env, "ThrownException::class_name")?;
        let class_name: JObject = call_method_checked(
            env,
            class_type,
            "getCanonicalName",
            jni_args!(() -> java.lang.String),
        )?;

        Ok(env
            .get_string(&JString::from(class_name))
            .check_exceptions(env, "ThrownException::class_name")?
            .into())
    }

    pub fn message(&self, env: &mut JNIEnv) -> Result<String, BridgeLayerError> {
        let message: JObject = call_method_checked(
            env,
            self.exception_ref.as_obj(),
            "getMessage",
            jni_args!(() -> java.lang.String),
        )?;
        Ok(env
            .get_string(&JString::from(message))
            .check_exceptions(env, "ThrownException::class_name")?
            .into())
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

pub trait HandleJniError<T> {
    fn check_exceptions(
        self,
        env: &mut JNIEnv<'_>,
        context: &'static str,
    ) -> Result<T, BridgeLayerError>;

    fn expect_no_exceptions(self) -> Result<T, BridgeLayerError>;
}

impl<T> HandleJniError<T> for Result<T, jni::errors::Error> {
    fn check_exceptions(
        self,
        env: &mut JNIEnv<'_>,
        context: &'static str,
    ) -> Result<T, BridgeLayerError> {
        // Do the bulk of the work in a non-generic helper function.
        fn check_error(
            e: jni::errors::Error,
            env: &mut JNIEnv<'_>,
            context: &'static str,
        ) -> Result<std::convert::Infallible, BridgeLayerError> {
            // Returning a Result is convenient because it lets us use ?, but it is always an error,
            // so we use Infallible as the success type, which can't be instantiated.
            if matches!(e, jni::errors::Error::JavaException) {
                let throwable = env.exception_occurred().expect_no_exceptions()?;
                if **throwable != *JObject::null() {
                    env.exception_clear().expect_no_exceptions()?;
                    return Err(BridgeLayerError::CallbackException(
                        context,
                        ThrownException::new(env, throwable)?,
                    ));
                }
                log::warn!(
                    "'{context}' produced a Java exception, but it has already been cleared from the JVM state"
                );
            }
            Err(BridgeLayerError::Jni(e))
        }

        self.map_err(|e| match check_error(e, env, context) {
            // min_exhaustive_patterns was stabilized in 1.82-nightly, which made the
            // unreachable_patterns lint much more aggressive. The lint was turned back down in
            // 1.83-nightly and 1.82-beta, but our pinned nightly is between the two changes.
            // We can remove the allow when we update our nightly toolchain (but we may eventually
            // have to put it back). We can remove the entire match arm when our MSRV is 1.82+.
            #[allow(unreachable_patterns)]
            Ok(_) => unreachable!(),
            Err(e) => e,
        })
    }

    fn expect_no_exceptions(self) -> Result<T, BridgeLayerError> {
        self.map_err(|e| {
            assert!(
                !matches!(e, jni::errors::Error::JavaException),
                "catching Java exceptions is not supported here"
            );
            BridgeLayerError::Jni(e)
        })
    }
}
