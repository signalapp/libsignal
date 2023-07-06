//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::objects::{GlobalRef, JObject, JString, JThrowable};
use jni::{JNIEnv, JavaVM};
use std::fmt;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use attest::hsm_enclave::Error as HsmEnclaveError;
use device_transfer::Error as DeviceTransferError;
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use signal_pin::Error as PinError;
use usernames::{UsernameError, UsernameLinkError};
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use crate::support::describe_panic;

use super::*;

/// The top-level error type for when something goes wrong.
#[derive(Debug)]
pub enum SignalJniError {
    Signal(SignalProtocolError),
    DeviceTransfer(DeviceTransferError),
    SignalCrypto(SignalCryptoError),
    HsmEnclave(HsmEnclaveError),
    Sgx(SgxError),
    Pin(PinError),
    ZkGroupDeserializationFailure(ZkGroupDeserializationFailure),
    ZkGroupVerificationFailure(ZkGroupVerificationFailure),
    UsernameError(UsernameError),
    UsernameLinkError(UsernameLinkError),
    Io(IoError),
    #[cfg(feature = "signal-media")]
    MediaSanitizeParse(signal_media::sanitize::ParseErrorReport),
    Jni(jni::errors::Error),
    BadJniParameter(&'static str),
    UnexpectedJniResultType(&'static str, &'static str),
    NullHandle,
    IntegerOverflow(String),
    IncorrectArrayLength {
        expected: usize,
        actual: usize,
    },
    UnexpectedPanic(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
}

impl fmt::Display for SignalJniError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignalJniError::Signal(s) => write!(f, "{}", s),
            SignalJniError::DeviceTransfer(s) => write!(f, "{}", s),
            SignalJniError::HsmEnclave(e) => write!(f, "{}", e),
            SignalJniError::Sgx(e) => write!(f, "{}", e),
            SignalJniError::Pin(e) => write!(f, "{}", e),
            SignalJniError::SignalCrypto(s) => write!(f, "{}", s),
            SignalJniError::ZkGroupVerificationFailure(e) => write!(f, "{}", e),
            SignalJniError::ZkGroupDeserializationFailure(e) => write!(f, "{}", e),
            SignalJniError::UsernameError(e) => write!(f, "{}", e),
            SignalJniError::UsernameLinkError(e) => write!(f, "{}", e),
            SignalJniError::Io(e) => write!(f, "{}", e),
            #[cfg(feature = "signal-media")]
            SignalJniError::MediaSanitizeParse(e) => write!(f, "{}", e),
            SignalJniError::Jni(s) => write!(f, "JNI error {}", s),
            SignalJniError::NullHandle => write!(f, "null handle"),
            SignalJniError::BadJniParameter(m) => write!(f, "bad parameter type {}", m),
            SignalJniError::UnexpectedJniResultType(m, t) => {
                write!(f, "calling {} returned unexpected type {}", m, t)
            }
            SignalJniError::IntegerOverflow(m) => {
                write!(f, "integer overflow during conversion of {}", m)
            }
            SignalJniError::IncorrectArrayLength { expected, actual } => {
                write!(
                    f,
                    "expected array with length {} (was {})",
                    expected, actual
                )
            }
            SignalJniError::UnexpectedPanic(e) => {
                write!(f, "unexpected panic: {}", describe_panic(e))
            }
        }
    }
}

impl From<SignalProtocolError> for SignalJniError {
    fn from(e: SignalProtocolError) -> SignalJniError {
        SignalJniError::Signal(e)
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

impl From<SgxError> for SignalJniError {
    fn from(e: SgxError) -> SignalJniError {
        SignalJniError::Sgx(e)
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

impl From<UsernameLinkError> for SignalJniError {
    fn from(e: UsernameLinkError) -> Self {
        SignalJniError::UsernameLinkError(e)
    }
}

impl From<IoError> for SignalJniError {
    fn from(e: IoError) -> SignalJniError {
        Self::Io(e)
    }
}

#[cfg(feature = "signal-media")]
impl From<signal_media::sanitize::Error> for SignalJniError {
    fn from(e: signal_media::sanitize::Error) -> Self {
        use signal_media::sanitize::Error;
        match e {
            Error::Io(e) => Self::Io(e.into()),
            Error::Parse(e) => Self::MediaSanitizeParse(e),
        }
    }
}

impl From<jni::errors::Error> for SignalJniError {
    fn from(e: jni::errors::Error) -> SignalJniError {
        SignalJniError::Jni(e)
    }
}

impl From<SignalJniError> for SignalProtocolError {
    fn from(err: SignalJniError) -> SignalProtocolError {
        match err {
            SignalJniError::Signal(e) => e,
            SignalJniError::Jni(e) => SignalProtocolError::FfiBindingError(e.to_string()),
            SignalJniError::BadJniParameter(m) => {
                SignalProtocolError::InvalidArgument(m.to_string())
            }
            _ => SignalProtocolError::FfiBindingError(format!("{}", err)),
        }
    }
}

impl From<SignalJniError> for IoError {
    fn from(err: SignalJniError) -> Self {
        match err {
            SignalJniError::Io(e) => e,
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
    pub fn as_obj(&self) -> JThrowable<'_> {
        self.exception_ref.as_obj().into()
    }

    /// Persists the given throwable.
    pub fn new<'a>(env: &JNIEnv<'a>, throwable: JThrowable<'a>) -> Result<Self, SignalJniError> {
        assert!(**throwable != *JObject::null());
        Ok(Self {
            jvm: env.get_java_vm()?,
            exception_ref: env.new_global_ref(throwable)?,
        })
    }

    pub fn class_name(&self, env: &JNIEnv) -> Result<String, SignalJniError> {
        let class_type = env.get_object_class(self.exception_ref.as_obj())?;
        let class_name: JObject = call_method_checked(
            env,
            class_type,
            "getCanonicalName",
            jni_args!(() -> java.lang.String),
        )?;

        Ok(env.get_string(JString::from(class_name))?.into())
    }

    pub fn message(&self, env: &JNIEnv) -> Result<String, SignalJniError> {
        let message: JObject = call_method_checked(
            env,
            self.exception_ref.as_obj(),
            "getMessage",
            jni_args!(() -> java.lang.String),
        )?;
        Ok(env.get_string(JString::from(message))?.into())
    }
}

impl fmt::Display for ThrownException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let env = &self.jvm.attach_current_thread().map_err(|_| fmt::Error)?;

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
        let env = &self.jvm.attach_current_thread().map_err(|_| fmt::Error)?;

        let exn_type = self.class_name(env);
        let exn_type = exn_type.as_deref().unwrap_or("<unknown>");

        let obj_addr = *self.exception_ref.as_obj();

        if let Ok(message) = self.message(env) {
            write!(f, "exception {} ({:p}) \"{}\"", exn_type, obj_addr, message)
        } else {
            write!(f, "exception {} ({:p})", exn_type, obj_addr)
        }
    }
}

impl std::error::Error for ThrownException {}
