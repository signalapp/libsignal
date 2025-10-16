//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::fmt::{self, Debug};
use std::io::Error as IoError;

use jni::objects::{AutoLocal, GlobalRef, JObject, JString, JThrowable};
use jni::{JNIEnv, JavaVM};

use super::*;
use crate::net::cdsi::CdsiError;
use crate::support::describe_panic;

/// The top-level error type for when something goes wrong.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SignalJniError(Box<dyn JniError + Send>);

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// TestingError({exception_class})
pub struct TestingError {
    pub exception_class: ClassName<'static>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// no connection attempts succeeded before timeout
pub(super) struct AllConnectionAttemptsFailed;

impl SignalJniError {
    #[cold]
    pub(super) fn to_throwable<'a>(
        &self,
        env: &mut JNIEnv<'a>,
    ) -> Result<JThrowable<'a>, BridgeLayerError> {
        self.0.to_throwable_impl(env).or_else(|convert_error| {
            // Recover by producing *some* throwable (AssertionError). This is particularly important
            // for Futures, which will otherwise hang. However, if this fails, give up and return the
            // *original* BridgeLayerError.
            try_scoped(|| {
                let message = env
                    .new_string(format!(
                        "failed to convert error \"{self}\": {convert_error}"
                    ))
                    .check_exceptions(env, "JniError::into_throwable")?;
                let error_obj = new_instance(
                    env,
                    ClassName("java.lang.AssertionError"),
                    jni_args!((message => java.lang.Object) -> void),
                )?;
                Ok(error_obj.into())
            })
            .map_err(|_: BridgeLayerError| convert_error)
        })
    }
}

pub(super) trait JniError: Debug + Display {
    fn to_throwable_impl<'a>(
        &self,
        env: &mut JNIEnv<'a>,
    ) -> Result<JThrowable<'a>, BridgeLayerError>;
}

/// Simpler trait that provides a blanket impl of [`JniError`].
///
/// This should only be implemented for types that, when converted into a Java
/// `Throwable`, create a class using a constructor that takes a single
/// `message` argument of type `java.lang.String`.
pub(super) trait MessageOnlyExceptionJniError: Debug + Display {
    /// The name of the Java class that a value can be converted into.
    fn exception_class(&self) -> ClassName<'static>;
}

impl<M: MessageOnlyExceptionJniError> JniError for M {
    fn to_throwable_impl<'a>(
        &self,
        env: &mut JNIEnv<'a>,
    ) -> Result<JThrowable<'a>, BridgeLayerError> {
        let class = self.exception_class();
        let throwable = env
            .new_string(self.to_string())
            .check_exceptions(env, "JniError::into_throwable")
            .and_then(|message| {
                new_instance(env, class, jni_args!((message => java.lang.String) -> void))
            });
        throwable.map(Into::into)
    }
}

impl<E> From<E> for SignalJniError
where
    E: JniError + Send + 'static,
{
    fn from(value: E) -> Self {
        Self(Box::new(value))
    }
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

impl fmt::Display for BridgeLayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jni(s) => write!(f, "JNI error {s}"),
            Self::NullPointer(None) => write!(f, "unexpected null"),
            Self::NullPointer(Some(expected_type)) => {
                write!(f, "got null where {expected_type} instance is expected")
            }
            Self::BadArgument(m) => write!(f, "{m}"),
            Self::BadJniParameter(m) => write!(f, "bad parameter type {m}"),
            Self::UnexpectedJniResultType(m, t) => {
                write!(f, "calling {m} returned unexpected type {t}")
            }
            Self::IntegerOverflow(m) => {
                write!(f, "integer overflow during conversion of {m}")
            }
            Self::IncorrectArrayLength { expected, actual } => {
                write!(f, "expected array with length {expected} (was {actual})")
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
            Error::Io(e) => e.into(),
            Error::Parse(e) => e.into(),
        }
    }
}

#[cfg(feature = "signal-media")]
impl From<signal_media::sanitize::webp::Error> for SignalJniError {
    fn from(e: signal_media::sanitize::webp::Error) -> Self {
        use signal_media::sanitize::webp::Error;
        match e {
            Error::Io(e) => e.into(),
            Error::Parse(e) => e.into(),
        }
    }
}

impl From<libsignal_net::cdsi::LookupError> for SignalJniError {
    fn from(e: libsignal_net::cdsi::LookupError) -> SignalJniError {
        use libsignal_net::cdsi::LookupError;
        let cdsi_error = match e {
            LookupError::AllConnectionAttemptsFailed => return AllConnectionAttemptsFailed.into(),
            LookupError::AttestationError(e) => return e.into(),
            LookupError::ConnectTransport(e) => return IoError::from(e).into(),
            LookupError::WebSocket(e) => return e.into(),
            LookupError::InvalidArgument { server_reason: _ } => {
                // Normally we wouldn't produce an unchecked error for something validated
                // server-side, but getting an argument validation error for *CDS* does suggest that
                // the operation was performed with bad arguments.
                return IllegalArgumentError::new(e.to_string()).into();
            }
            LookupError::EnclaveProtocol(_) => CdsiError::Protocol,
            LookupError::CdsiProtocol(inner) => CdsiError::CdsiProtocol(inner),
            LookupError::RateLimited(retry_later) => CdsiError::RateLimited(retry_later),
            LookupError::InvalidToken => CdsiError::InvalidToken,
            LookupError::Server { reason } => CdsiError::Server { reason },
        };
        CdsiError::into(cdsi_error)
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
        let class_type = AutoLocal::new(
            env.get_object_class(self.exception_ref.as_obj())
                .check_exceptions(env, "ThrownException::class_name")?,
            env,
        );
        let class_name = AutoLocal::new(
            JString::from(call_method_checked(
                env,
                class_type,
                "getCanonicalName",
                jni_args!(() -> java.lang.String),
            )?),
            env,
        );
        let class_name_str = env
            .get_string(&class_name)
            .check_exceptions(env, "ThrownException::class_name")?;
        Ok(class_name_str.into())
    }

    pub fn message(&self, env: &mut JNIEnv) -> Result<String, BridgeLayerError> {
        let message = AutoLocal::new(
            JString::from(call_method_checked(
                env,
                self.exception_ref.as_obj(),
                "getMessage",
                jni_args!(() -> java.lang.String),
            )?),
            env,
        );
        let message_str = env
            .get_string(&message)
            .check_exceptions(env, "ThrownException::message")?;
        Ok(message_str.into())
    }
}

impl fmt::Display for ThrownException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let env = &mut self.jvm.attach_current_thread().map_err(|_| fmt::Error)?;

        let exn_type = self.class_name(env);
        let exn_type = exn_type.as_deref().unwrap_or("<unknown>");

        if let Ok(message) = self.message(env) {
            write!(f, "exception {exn_type} \"{message}\"")
        } else {
            write!(f, "exception {exn_type}")
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
            write!(f, "exception {exn_type} ({obj_addr:p}) \"{message}\"")
        } else {
            write!(f, "exception {exn_type} ({obj_addr:p})")
        }
    }
}

impl std::error::Error for ThrownException {}

/// Error output when a future is cancelled.
#[derive(Debug, thiserror::Error)]
#[error("the future was cancelled")]
pub struct FutureCancelled;

impl MessageOnlyExceptionJniError for FutureCancelled {
    fn exception_class(&self) -> ClassName<'static> {
        ClassName("java.util.concurrent.CancellationException")
    }
}

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
