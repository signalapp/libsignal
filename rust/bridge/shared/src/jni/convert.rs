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

pub(crate) trait TrivialTypeInfo {}

impl<'a, T: TrivialTypeInfo> ArgTypeInfo<'a> for T {
    type ArgType = Self;
    fn convert_from(_env: &JNIEnv<'a>, foreign: Self) -> Result<Self, SignalJniError> { Ok(foreign) }
}

impl<'a, T: TrivialTypeInfo> ResultTypeInfo<'a> for T {
    type ResultType = Self;
    fn convert_into(self, _env: &JNIEnv<'a>) -> Result<Self, SignalJniError> { Ok(self) }
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

impl<'a> ResultTypeInfo<'a> for ProtocolAddress {
    type ResultType = ObjectHandle;
    fn convert_into(self, _env: &JNIEnv<'a>) -> Result<Self::ResultType, SignalJniError> {
        box_object(Ok(self))
    }
}

macro_rules! jni_arg_type {
    (u32) => (jni::jint);
    (String) => (jni::JString);
}

macro_rules! jni_result_type {
    ( $typ:ty ) => (jni::ObjectHandle);
}
