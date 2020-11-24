//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::JNIEnv;
use jni::objects::JString;
use libsignal_protocol_rust::*;

use crate::jni::*;

pub(crate) trait ArgTypeInfo<'a>: Sized {
    type ArgType;
    fn convert_from(env: &JNIEnv<'a>, foreign: Self::ArgType) -> Result<Self, SignalJniError>;
}

pub(crate) trait ResultTypeInfo<'a>: Sized {
    type ResultType;
    fn convert_into(self, env: &JNIEnv<'a>) -> Result<Self::ResultType, SignalJniError>;
}

impl<'a> ArgTypeInfo<'a> for u32 {
    type ArgType = jint;
    fn convert_from(_env: &JNIEnv<'a>, foreign: jint) -> Result<Self, SignalJniError> {
        jint_to_u32(foreign)
    }
}

impl<'a> ArgTypeInfo<'a> for String {
    type ArgType = JString<'a>;
    fn convert_from(env: &JNIEnv<'a>, foreign: JString<'a>) -> Result<Self, SignalJniError> {
        Ok(env.get_string(foreign)?.into())
    }
}

impl<'a, T> ArgTypeInfo<'a> for &'static T {
    type ArgType = ObjectHandle;
    fn convert_from(_env: &JNIEnv<'a>, foreign: Self::ArgType) -> Result<Self, SignalJniError> {
        Ok(unsafe { native_handle_cast(foreign) }?)
    }
}

impl<'a> ResultTypeInfo<'a> for ProtocolAddress {
    type ResultType = ObjectHandle;
    fn convert_into(self, _env: &JNIEnv<'a>) -> Result<Self::ResultType, SignalJniError> {
        box_object(Ok(self))
    }
}

macro_rules! trivial {
    ($typ:ty) => {
        impl<'a> ArgTypeInfo<'a> for $typ {
            type ArgType = Self;
            fn convert_from(_env: &JNIEnv<'a>, foreign: Self) -> Result<Self, SignalJniError> { Ok(foreign) }
        }
        impl<'a> ResultTypeInfo<'a> for $typ {
            type ResultType = Self;
            fn convert_into(self, _env: &JNIEnv<'a>) -> Result<Self, SignalJniError> { Ok(self) }
        }
    }
}

trivial!(i32);

macro_rules! jni_arg_type {
    (u32) => (jni::jint);
    (String) => (jni::JString);
    (& $typ:ty) => (jni::ObjectHandle);
}

macro_rules! jni_result_type {
    (i32) => (jni::jint);
    ( $typ:ty ) => (jni::ObjectHandle);
}
