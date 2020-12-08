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

#[derive(thiserror::Error, Debug)]
pub enum SignalJniError {
    #[error(transparent)]
    Signal(#[from] SignalProtocolError),
    #[error(transparent)]
    AesGcmSiv(#[from] AesGcmSivError),
    #[error(transparent)]
    Jni(#[from] jni::errors::Error),
    #[error("bad parameter type {0}")]
    BadJniParameter(&'static str),
    #[error("calling {0} returned unexpected type {1}")]
    UnexpectedJniResultType(&'static str, &'static str),
    #[error("null handle")]
    NullHandle,
    #[error("integer overflow during conversion of {0}")]
    IntegerOverflow(String),
    #[error("{}", .0.downcast_ref::<&'static str>().map(|s| format!("unexpected panic: {}", s)).unwrap_or_else(|| "unknown unexpected panic".to_owned()))]
    UnexpectedPanic(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
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
