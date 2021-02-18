//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::objects::{AutoByteArray, JString, ReleaseMode};
use jni::sys::{JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use libsignal_protocol::*;
use std::borrow::Cow;

use super::*;

pub(crate) trait ArgTypeInfo<'storage, 'context: 'storage>: Sized {
    type ArgType;
    type StoredType;
    fn borrow(
        env: &'context JNIEnv,
        foreign: Self::ArgType,
    ) -> Result<Self::StoredType, SignalJniError>;
    fn load_from(
        env: &JNIEnv,
        stored: &'storage mut Self::StoredType,
    ) -> Result<Self, SignalJniError>;
}

pub(crate) trait SimpleArgTypeInfo<'a>: Sized {
    type ArgType: Copy + 'a;
    fn convert_from(env: &JNIEnv, foreign: Self::ArgType) -> Result<Self, SignalJniError>;
}

impl<'a, T> ArgTypeInfo<'a, 'a> for T
where
    T: SimpleArgTypeInfo<'a>,
{
    type ArgType = <Self as SimpleArgTypeInfo<'a>>::ArgType;
    type StoredType = Self::ArgType;
    fn borrow(
        _env: &'a JNIEnv,
        foreign: Self::ArgType,
    ) -> Result<Self::StoredType, SignalJniError> {
        Ok(foreign)
    }
    fn load_from(env: &JNIEnv, stored: &'a mut Self::StoredType) -> Result<Self, SignalJniError> {
        Self::convert_from(env, *stored)
    }
}

pub(crate) trait ResultTypeInfo: Sized {
    type ResultType;
    fn convert_into(self, env: &JNIEnv) -> Result<Self::ResultType, SignalJniError>;
}

impl<'a> SimpleArgTypeInfo<'a> for u32 {
    type ArgType = jint;
    fn convert_from(_env: &JNIEnv, foreign: jint) -> Result<Self, SignalJniError> {
        jint_to_u32(foreign)
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Option<u32> {
    type ArgType = jint;
    fn convert_from(env: &JNIEnv, foreign: jint) -> Result<Self, SignalJniError> {
        if foreign < 0 {
            Ok(None)
        } else {
            u32::convert_from(env, foreign).map(Some)
        }
    }
}

impl<'a> SimpleArgTypeInfo<'a> for u64 {
    type ArgType = jlong;
    fn convert_from(_env: &JNIEnv, foreign: jlong) -> Result<Self, SignalJniError> {
        jlong_to_u64(foreign)
    }
}

impl<'a> SimpleArgTypeInfo<'a> for u8 {
    type ArgType = jint;
    fn convert_from(_env: &JNIEnv, foreign: jint) -> Result<Self, SignalJniError> {
        jint_to_u8(foreign)
    }
}

impl<'a> SimpleArgTypeInfo<'a> for String {
    type ArgType = JString<'a>;
    fn convert_from(env: &JNIEnv, foreign: JString<'a>) -> Result<Self, SignalJniError> {
        Ok(env.get_string(foreign)?.into())
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Option<String> {
    type ArgType = JString<'a>;
    fn convert_from(env: &JNIEnv, foreign: JString<'a>) -> Result<Self, SignalJniError> {
        if foreign.is_null() {
            Ok(None)
        } else {
            String::convert_from(env, foreign).map(Some)
        }
    }
}

pub(crate) struct AutoByteSlice<'a> {
    jni_array: AutoByteArray<'a, 'a>,
    len: usize,
}

impl<'storage, 'context: 'storage> ArgTypeInfo<'storage, 'context> for &'storage [u8] {
    type ArgType = jbyteArray;
    type StoredType = AutoByteSlice<'context>;
    fn borrow(
        env: &'context JNIEnv,
        foreign: Self::ArgType,
    ) -> Result<Self::StoredType, SignalJniError> {
        let len = env.get_array_length(foreign)?;
        assert!(len >= 0);
        Ok(AutoByteSlice {
            jni_array: env.get_auto_byte_array_elements(foreign, ReleaseMode::NoCopyBack)?,
            len: len as usize,
        })
    }
    fn load_from(
        _env: &JNIEnv,
        stored: &'storage mut Self::StoredType,
    ) -> Result<&'storage [u8], SignalJniError> {
        Ok(unsafe {
            std::slice::from_raw_parts(stored.jni_array.as_ptr() as *const u8, stored.len)
        })
    }
}

impl<'storage, 'context: 'storage> ArgTypeInfo<'storage, 'context> for Option<&'storage [u8]> {
    type ArgType = jbyteArray;
    type StoredType = Option<AutoByteSlice<'context>>;
    fn borrow(
        env: &'context JNIEnv,
        foreign: Self::ArgType,
    ) -> Result<Self::StoredType, SignalJniError> {
        if foreign.is_null() {
            Ok(None)
        } else {
            <&'storage [u8]>::borrow(env, foreign).map(Some)
        }
    }
    fn load_from(
        env: &JNIEnv,
        stored: &'storage mut Self::StoredType,
    ) -> Result<Option<&'storage [u8]>, SignalJniError> {
        stored
            .as_mut()
            .map(|s| <&'storage [u8]>::load_from(env, s))
            .transpose()
    }
}

impl ResultTypeInfo for bool {
    type ResultType = jboolean;
    fn convert_into(self, _env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        Ok(if self { JNI_TRUE } else { JNI_FALSE })
    }
}

impl ResultTypeInfo for u8 {
    type ResultType = jint;
    fn convert_into(self, _env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        Ok(self as jint)
    }
}

impl ResultTypeInfo for u32 {
    type ResultType = jint;
    fn convert_into(self, _env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        // Note that we don't check bounds here.
        Ok(self as jint)
    }
}

impl ResultTypeInfo for Option<u32> {
    type ResultType = jint;
    fn convert_into(self, _env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        // Note that we don't check bounds here.
        Ok(self.unwrap_or(u32::MAX) as jint)
    }
}

impl ResultTypeInfo for u64 {
    type ResultType = jlong;
    fn convert_into(self, _env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        // Note that we don't check bounds here.
        Ok(self as jlong)
    }
}

impl ResultTypeInfo for String {
    type ResultType = jstring;
    fn convert_into(self, env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        Ok(env.new_string(self)?.into_inner())
    }
}

impl ResultTypeInfo for Option<String> {
    type ResultType = jstring;
    fn convert_into(self, env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        match self {
            Some(s) => s.convert_into(env),
            None => Ok(std::ptr::null_mut()),
        }
    }
}

impl ResultTypeInfo for &str {
    type ResultType = jstring;
    fn convert_into(self, env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        Ok(env.new_string(self)?.into_inner())
    }
}

impl ResultTypeInfo for Option<&str> {
    type ResultType = jstring;
    fn convert_into(self, env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        match self {
            Some(s) => s.convert_into(env),
            None => Ok(std::ptr::null_mut()),
        }
    }
}

impl ResultTypeInfo for Vec<u8> {
    type ResultType = jbyteArray;
    fn convert_into(self, env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        Ok(env.byte_array_from_slice(&self)?)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, SignalProtocolError> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        T::convert_into(self?, env)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, aes_gcm_siv::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        T::convert_into(self?, env)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, SignalJniError> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        T::convert_into(self?, env)
    }
}

impl<T> ResultTypeInfo for Option<Result<T, SignalJniError>>
where
    Option<T>: ResultTypeInfo,
{
    type ResultType = <Option<T> as ResultTypeInfo>::ResultType;
    fn convert_into(self, env: &jni::JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        self.transpose()?.convert_into(env)
    }
}

impl ResultTypeInfo for Option<jobject> {
    type ResultType = jobject;
    fn convert_into(self, _env: &jni::JNIEnv) -> Result<Self::ResultType, SignalJniError> {
        Ok(self.unwrap_or(std::ptr::null_mut()))
    }
}

impl crate::Env for &'_ JNIEnv<'_> {
    type Buffer = Result<jbyteArray, SignalJniError>;
    fn buffer<'a, T: Into<Cow<'a, [u8]>>>(self, input: T) -> Self::Buffer {
        to_jbytearray(&self, Ok(input.into()))
    }
}

macro_rules! jni_bridge_handle {
    ( $typ:ty as false ) => {};
    ( $typ:ty as $jni_name:ident ) => {
        impl<'a> jni::SimpleArgTypeInfo<'a> for &$typ {
            type ArgType = jni::ObjectHandle;
            fn convert_from(
                _env: &jni::JNIEnv,
                foreign: Self::ArgType,
            ) -> Result<Self, jni::SignalJniError> {
                Ok(unsafe { jni::native_handle_cast(foreign) }?)
            }
        }
        impl<'a> jni::SimpleArgTypeInfo<'a> for Option<&$typ> {
            type ArgType = jni::ObjectHandle;
            fn convert_from(
                env: &jni::JNIEnv,
                foreign: Self::ArgType,
            ) -> Result<Self, jni::SignalJniError> {
                if foreign == 0 {
                    Ok(None)
                } else {
                    <&$typ>::convert_from(env, foreign).map(Some)
                }
            }
        }
        impl<'a> jni::SimpleArgTypeInfo<'a> for &mut $typ {
            type ArgType = jni::ObjectHandle;
            fn convert_from(
                _env: &jni::JNIEnv,
                foreign: Self::ArgType,
            ) -> Result<Self, jni::SignalJniError> {
                Ok(unsafe { jni::native_handle_cast(foreign) }?)
            }
        }
        impl jni::ResultTypeInfo for $typ {
            type ResultType = jni::ObjectHandle;
            fn convert_into(
                self,
                _env: &jni::JNIEnv,
            ) -> Result<Self::ResultType, jni::SignalJniError> {
                jni::box_object(Ok(self))
            }
        }
        impl jni::ResultTypeInfo for Option<$typ> {
            type ResultType = jni::ObjectHandle;
            fn convert_into(
                self,
                env: &jni::JNIEnv,
            ) -> Result<Self::ResultType, jni::SignalJniError> {
                match self {
                    Some(obj) => obj.convert_into(env),
                    None => Ok(0),
                }
            }
        }
        jni_bridge_destroy!($typ as $jni_name);
    };
    ( $typ:ty ) => {
        paste! {
            jni_bridge_handle!($typ as $typ);
        }
    };
}

macro_rules! trivial {
    ($typ:ty) => {
        impl<'a> SimpleArgTypeInfo<'a> for $typ {
            type ArgType = Self;
            fn convert_from(_env: &JNIEnv, foreign: Self) -> Result<Self, SignalJniError> {
                Ok(foreign)
            }
        }
        impl ResultTypeInfo for $typ {
            type ResultType = Self;
            fn convert_into(self, _env: &JNIEnv) -> Result<Self, SignalJniError> {
                Ok(self)
            }
        }
    };
}

trivial!(i32);
trivial!(jbyteArray);
trivial!(());

macro_rules! jni_arg_type {
    (u8) => {
        // Note: not a jbyte. It's better to preserve the signedness here.
        jni::jint
    };
    (u32) => {
        jni::jint
    };
    (Option<u32>) => {
        jni::jint
    };
    (u64) => {
        jni::jlong
    };
    (String) => {
        jni::JString
    };
    (Option<String>) => {
        jni::JString
    };
    (&[u8]) => {
        jni::jbyteArray
    };
    (Option<&[u8]>) => {
        jni::jbyteArray
    };
    (& $typ:ty) => {
        jni::ObjectHandle
    };
    (&mut $typ:ty) => {
        jni::ObjectHandle
    };
    (Option<& $typ:ty>) => {
        jni::ObjectHandle
    };
}

macro_rules! jni_result_type {
    (Result<$typ:tt, $_:ty>) => {
        jni_result_type!($typ)
    };
    (Result<&$typ:tt, $_:ty>) => {
        jni_result_type!(&$typ)
    };
    (Result<Option<&$typ:tt>, $_:ty>) => {
        jni_result_type!(&$typ)
    };
    (Result<$typ:tt<$($args:tt),+>, $_:ty>) => {
        jni_result_type!($typ<$($args)+>)
    };
    (bool) => {
        jni::jboolean
    };
    (u8) => {
        // Note: not a jbyte. It's better to preserve the signedness here.
        jni::jint
    };
    (i32) => {
        jni::jint
    };
    (u32) => {
        jni::jint
    };
    (u64) => {
        jni::jlong
    };
    (Option<u32>) => {
        jni::jint
    };
    (&str) => {
        jni::jstring
    };
    (String) => {
        jni::jstring
    };
    (Option<String>) => {
        jni::jstring
    };
    (Option<&str>) => {
        jni::jstring
    };
    (Vec<u8>) => {
        jni::jbyteArray
    };
    ( $typ:ty ) => {
        jni::ObjectHandle
    };
}
