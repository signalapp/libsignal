//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::JNIEnv;
use jni::objects::{AutoByteArray, JString, ReleaseMode};
use jni::sys::{JNI_FALSE, JNI_TRUE};
use libsignal_protocol_rust::*;
use std::borrow::Borrow;
use std::ops::Deref;

use crate::jni::*;

pub(crate) trait ArgTypeInfo<'a>: Sized {
    type ArgType;
    fn convert_from(env: &'a JNIEnv, foreign: Self::ArgType) -> Result<Self, SignalJniError>;
}

pub(crate) trait RefArgTypeInfo<'a>: Deref {
    type ArgType;
    type StoredType: Borrow<Self::Target> + 'a;
    fn convert_from(env: &'a JNIEnv, foreign: Self::ArgType) -> Result<Self::StoredType, SignalJniError>;
}

pub(crate) trait ResultTypeInfo: Sized {
    type ResultType;
    fn convert_into(self, env: &JNIEnv) -> Result<Self::ResultType, SignalJniError>;
}

impl<'a> ArgTypeInfo<'a> for u32 {
    type ArgType = jint;
    fn convert_from(_env: &'a JNIEnv, foreign: jint) -> Result<Self, SignalJniError> {
        jint_to_u32(foreign)
    }
}

impl<'a> ArgTypeInfo<'a> for Option<u32> {
    type ArgType = jint;
    fn convert_from(env: &'a JNIEnv, foreign: jint) -> Result<Self, SignalJniError> {
        if foreign < 0 {
            Ok(None)
        } else {
            u32::convert_from(env, foreign).map(Some)
        }
    }
}

impl<'a> ArgTypeInfo<'a> for u8 {
    type ArgType = jint;
    fn convert_from(_env: &'a JNIEnv, foreign: jint) -> Result<Self, SignalJniError> {
        jint_to_u8(foreign)
    }
}

impl<'a> ArgTypeInfo<'a> for String {
    type ArgType = JString<'a>;
    fn convert_from(env: &'a JNIEnv, foreign: JString<'a>) -> Result<Self, SignalJniError> {
        Ok(env.get_string(foreign)?.into())
    }
}

pub(crate) struct AutoByteSlice<'a> {
    jni_array: AutoByteArray<'a, 'a>,
    len: usize,
}

impl<'a> Borrow<[u8]> for AutoByteSlice<'a> {
    fn borrow(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.jni_array.as_ptr() as *const u8, self.len) }
    }
}

impl<'a> RefArgTypeInfo<'a> for &[u8] {
    type ArgType = jbyteArray;
    type StoredType = AutoByteSlice<'a>;
    fn convert_from(env: &'a JNIEnv, foreign: Self::ArgType) -> Result<Self::StoredType, SignalJniError> {
        let len = env.get_array_length(foreign)?;
        assert!(len >= 0);
        Ok(AutoByteSlice {
            jni_array: env.get_auto_byte_array_elements(foreign, ReleaseMode::NoCopyBack)?,
            len: len as usize,
        })
    }
}

impl ResultTypeInfo for bool {
    type ResultType = jboolean;
    fn convert_into(self, _env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        Ok(if self { JNI_TRUE } else { JNI_FALSE })
    }
}

impl ResultTypeInfo for String {
    type ResultType = jstring;
    fn convert_into(self, env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        Ok(env.new_string(self)?.into_inner())
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, SignalProtocolError> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        T::convert_into(self?, env)
    }
}

macro_rules! native_handle {
    ($typ:ty) => {
        impl<'a> RefArgTypeInfo<'a> for &$typ {
            type ArgType = ObjectHandle;
            type StoredType = &'static $typ;
            fn convert_from(_env: &'a JNIEnv, foreign: Self::ArgType) -> Result<Self::StoredType, SignalJniError> {
                Ok(unsafe { native_handle_cast(foreign) }?)
            }
        }
        impl ResultTypeInfo for $typ {
            type ResultType = ObjectHandle;
            fn convert_into(self, _env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
                box_object(Ok(self))
            }
        }
    }
}

native_handle!(PublicKey);
native_handle!(ProtocolAddress);
native_handle!(SignalMessage);
native_handle!(PreKeySignalMessage);

macro_rules! trivial {
    ($typ:ty) => {
        impl<'a> ArgTypeInfo<'a> for $typ {
            type ArgType = Self;
            fn convert_from(_env: &'a JNIEnv, foreign: Self) -> Result<Self, SignalJniError> { Ok(foreign) }
        }
        impl ResultTypeInfo for $typ {
            type ResultType = Self;
            fn convert_into(self, _env: &JNIEnv) -> Result<Self, SignalJniError> { Ok(self) }
        }
    }
}

trivial!(i32);

macro_rules! jni_arg_type {
    (u8) => (jni::jint);
    (u32) => (jni::jint);
    (Option<u32>) => (jni::jint);
    (String) => (jni::JString);
    (&[u8]) => (jni::jbyteArray);
    (& $typ:ty) => (jni::ObjectHandle);
}

macro_rules! jni_result_type {
    (Result<$typ:tt, $_:tt>) => (jni_result_type!($typ));
    (bool) => (jni::jboolean);
    (i32) => (jni::jint);
    (String) => (jni::jstring);
    ( $typ:ty ) => (jni::ObjectHandle);
}
