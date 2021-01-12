//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::objects::{GlobalRef, JObject, JString, JThrowable, JValue};
use jni::{JNIEnv, JavaVM};
use std::fmt;

use aes_gcm_siv::Error as AesGcmSivError;
use libsignal_protocol_rust::*;

use super::*;

#[derive(Debug)]
pub enum SignalJniError {
    Signal(SignalProtocolError),
    AesGcmSiv(AesGcmSivError),
    Jni(jni::errors::Error),
    BadJniParameter(&'static str),
    UnexpectedJniResultType(&'static str, &'static str),
    NullHandle,
    IntegerOverflow(String),
    UnexpectedPanic(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
}

impl fmt::Display for SignalJniError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignalJniError::Signal(s) => write!(f, "{}", s),
            SignalJniError::AesGcmSiv(s) => write!(f, "{}", s),
            SignalJniError::Jni(s) => write!(f, "JNI error {}", s),
            SignalJniError::NullHandle => write!(f, "null handle"),
            SignalJniError::BadJniParameter(m) => write!(f, "bad parameter type {}", m),
            SignalJniError::UnexpectedJniResultType(m, t) => {
                write!(f, "calling {} returned unexpected type {}", m, t)
            }
            SignalJniError::IntegerOverflow(m) => {
                write!(f, "integer overflow during conversion of {}", m)
            }
            SignalJniError::UnexpectedPanic(e) => match e.downcast_ref::<&'static str>() {
                Some(s) => write!(f, "unexpected panic: {}", s),
                None => write!(f, "unknown unexpected panic"),
            },
        }
    }
}

impl From<SignalProtocolError> for SignalJniError {
    fn from(e: SignalProtocolError) -> SignalJniError {
        SignalJniError::Signal(e)
    }
}

impl From<AesGcmSivError> for SignalJniError {
    fn from(e: AesGcmSivError) -> SignalJniError {
        SignalJniError::AesGcmSiv(e)
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

pub struct ThrownException {
    jvm: JavaVM,
    exception_ref: GlobalRef,
}

impl ThrownException {
    pub fn as_obj(&self) -> JThrowable {
        self.exception_ref.as_obj().into()
    }

    pub fn new<'a>(env: &JNIEnv<'a>, throwable: JThrowable<'a>) -> Result<Self, SignalJniError> {
        assert!(**throwable != *JObject::null());
        Ok(Self {
            jvm: env.get_java_vm()?,
            exception_ref: env.new_global_ref(throwable)?,
        })
    }

    pub fn class_name(&self, env: &JNIEnv) -> Result<String, SignalJniError> {
        let class_type = env.get_object_class(self.exception_ref.as_obj())?;
        let class_name = call_method_checked(
            env,
            class_type,
            "getCanonicalName",
            "()Ljava/lang/String;",
            &[],
        )?;

        if let JValue::Object(class_name) = class_name {
            let class_name: String = env.get_string(JString::from(class_name))?.into();
            Ok(class_name)
        } else {
            Err(SignalJniError::UnexpectedJniResultType(
                "getCanonicalName",
                class_name.type_name(),
            ))
        }
    }

    pub fn message(&self, env: &JNIEnv) -> Result<String, SignalJniError> {
        let message = call_method_checked(
            env,
            self.exception_ref.as_obj(),
            "getMessage",
            "()Ljava/lang/String;",
            &[],
        )?;
        if let JValue::Object(message) = message {
            Ok(env.get_string(JString::from(message))?.into())
        } else {
            Err(SignalJniError::UnexpectedJniResultType(
                "getMessage",
                message.type_name(),
            ))
        }
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
