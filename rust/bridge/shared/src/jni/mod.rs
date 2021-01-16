//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::objects::{JObject, JValue};
use jni::sys::jobject;

use aes_gcm_siv::Error as AesGcmSivError;
use libsignal_protocol_rust::*;
use std::convert::TryFrom;

pub(crate) use jni::objects::{JClass, JString};
pub(crate) use jni::strings::JNIString;
pub(crate) use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
pub(crate) use jni::JNIEnv;

#[macro_use]
mod convert;
pub(crate) use convert::*;

mod error;
pub use error::*;

pub use crate::support::expect_ready;

pub type ObjectHandle = jlong;

fn throw_error(env: &JNIEnv, error: SignalJniError) {
    // Handle special cases first.
    let error = match error {
        SignalJniError::Signal(SignalProtocolError::ApplicationCallbackError(
            callback,
            exception,
        )) => {
            match exception.downcast::<ThrownException>() {
                Ok(exception) => {
                    if let Err(e) = env.throw(exception.as_obj()) {
                        log::error!("failed to rethrow exception from {}: {}", callback, e);
                    }
                    return;
                }
                Err(other_underlying_error) => {
                    // Fall through to generic handling below.
                    SignalJniError::Signal(SignalProtocolError::ApplicationCallbackError(
                        callback,
                        other_underlying_error,
                    ))
                }
            }
        }

        SignalJniError::Signal(SignalProtocolError::UntrustedIdentity(ref addr)) => {
            let result = env.throw_new(
                "org/whispersystems/libsignal/UntrustedIdentityException",
                addr.name(),
            );
            if let Err(e) = result {
                log::error!("failed to throw exception for {}: {}", error, e);
            }
            return;
        }

        e => e,
    };

    let exception_type = match error {
        SignalJniError::NullHandle => "java/lang/NullPointerException",
        SignalJniError::UnexpectedPanic(_) => "java/lang/AssertionError",
        SignalJniError::BadJniParameter(_) => "java/lang/AssertionError",
        SignalJniError::UnexpectedJniResultType(_, _) => "java/lang/AssertionError",
        SignalJniError::IntegerOverflow(_) => "java/lang/RuntimeException",

        SignalJniError::Signal(SignalProtocolError::DuplicatedMessage(_, _)) => {
            "org/whispersystems/libsignal/DuplicateMessageException"
        }

        SignalJniError::Signal(SignalProtocolError::InvalidPreKeyId)
        | SignalJniError::Signal(SignalProtocolError::InvalidSignedPreKeyId)
        | SignalJniError::Signal(SignalProtocolError::InvalidSenderKeyId) => {
            "org/whispersystems/libsignal/InvalidKeyIdException"
        }

        SignalJniError::Signal(SignalProtocolError::NoKeyTypeIdentifier)
        | SignalJniError::Signal(SignalProtocolError::SignatureValidationFailed)
        | SignalJniError::Signal(SignalProtocolError::BadKeyType(_))
        | SignalJniError::Signal(SignalProtocolError::BadKeyLength(_, _))
        | SignalJniError::AesGcmSiv(AesGcmSivError::InvalidKeySize) => {
            "org/whispersystems/libsignal/InvalidKeyException"
        }

        SignalJniError::Signal(SignalProtocolError::SessionNotFound) => {
            "org/whispersystems/libsignal/NoSessionException"
        }

        SignalJniError::Signal(SignalProtocolError::InvalidMessage(_))
        | SignalJniError::Signal(SignalProtocolError::CiphertextMessageTooShort(_))
        | SignalJniError::Signal(SignalProtocolError::UnrecognizedCiphertextVersion(_))
        | SignalJniError::Signal(SignalProtocolError::UnrecognizedMessageVersion(_))
        | SignalJniError::Signal(SignalProtocolError::InvalidCiphertext)
        | SignalJniError::Signal(SignalProtocolError::InvalidProtobufEncoding)
        | SignalJniError::AesGcmSiv(AesGcmSivError::InvalidTag) => {
            "org/whispersystems/libsignal/InvalidMessageException"
        }

        SignalJniError::Signal(SignalProtocolError::LegacyCiphertextVersion(_)) => {
            "org/whispersystems/libsignal/LegacyMessageException"
        }

        SignalJniError::Signal(SignalProtocolError::InvalidState(_, _))
        | SignalJniError::Signal(SignalProtocolError::NoSenderKeyState)
        | SignalJniError::Signal(SignalProtocolError::InvalidSessionStructure) => {
            "java/lang/IllegalStateException"
        }

        SignalJniError::Signal(SignalProtocolError::SealedSenderSelfSend) => {
            "org/signal/libsignal/metadata/SelfSendException"
        }

        SignalJniError::Signal(SignalProtocolError::InvalidArgument(_))
        | SignalJniError::AesGcmSiv(_) => "java/lang/IllegalArgumentException",

        SignalJniError::Signal(_) => "java/lang/RuntimeException",

        SignalJniError::Jni(_) => "java/lang/RuntimeException",
    };

    if let Err(e) = env.throw_new(exception_type, error.to_string()) {
        log::error!("failed to throw exception for {}: {}", error, e);
    }
}

// A dummy value to return when we are throwing an exception
pub trait JniDummyValue {
    fn dummy_value() -> Self;
}

impl JniDummyValue for ObjectHandle {
    fn dummy_value() -> Self {
        0
    }
}

impl JniDummyValue for jint {
    fn dummy_value() -> Self {
        0
    }
}

impl JniDummyValue for jobject {
    fn dummy_value() -> Self {
        0 as jstring
    }
}

impl JniDummyValue for jboolean {
    fn dummy_value() -> Self {
        0
    }
}

impl JniDummyValue for () {
    fn dummy_value() -> Self {}
}

pub fn run_ffi_safe<F: FnOnce() -> Result<R, SignalJniError> + std::panic::UnwindSafe, R>(
    env: &JNIEnv,
    f: F,
) -> R
where
    R: JniDummyValue,
{
    match std::panic::catch_unwind(f) {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            throw_error(env, e);
            R::dummy_value()
        }
        Err(r) => {
            throw_error(env, SignalJniError::UnexpectedPanic(r));
            R::dummy_value()
        }
    }
}

pub fn box_object<T>(t: Result<T, SignalProtocolError>) -> Result<ObjectHandle, SignalJniError> {
    match t {
        Ok(t) => Ok(Box::into_raw(Box::new(t)) as ObjectHandle),
        Err(e) => Err(SignalJniError::Signal(e)),
    }
}

pub unsafe fn native_handle_cast<T>(
    handle: ObjectHandle,
) -> Result<&'static mut T, SignalJniError> {
    /*
    Should we try testing the encoded pointer for sanity here, beyond
    being null? For example verifying that lowest bits are zero,
    highest bits are zero, greater than 64K, etc?
    */
    if handle == 0 {
        return Err(SignalJniError::NullHandle);
    }

    Ok(&mut *(handle as *mut T))
}

pub fn jint_to_u32(v: jint) -> Result<u32, SignalJniError> {
    if v < 0 {
        return Err(SignalJniError::IntegerOverflow(format!("{} to u32", v)));
    }
    Ok(v as u32)
}

pub fn jint_to_u8(v: jint) -> Result<u8, SignalJniError> {
    match u8::try_from(v) {
        Err(_) => Err(SignalJniError::IntegerOverflow(format!("{} to u8", v))),
        Ok(v) => Ok(v),
    }
}

pub fn jlong_to_u64(v: jlong) -> Result<u64, SignalJniError> {
    if v < 0 {
        return Err(SignalJniError::IntegerOverflow(format!("{} to u64", v)));
    }
    Ok(v as u64)
}

pub fn to_jbytearray<T: AsRef<[u8]>>(
    env: &JNIEnv,
    data: Result<T, SignalProtocolError>,
) -> Result<jbyteArray, SignalJniError> {
    let data = data?;
    let data: &[u8] = data.as_ref();
    Ok(env.byte_array_from_slice(data)?)
}

pub fn call_method_checked<'a>(
    env: &JNIEnv<'a>,
    obj: impl Into<JObject<'a>>,
    fn_name: &'static str,
    sig: &'static str,
    args: &[JValue<'_>],
) -> Result<JValue<'a>, SignalJniError> {
    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    let result = env.call_method(obj, fn_name, sig, args);

    let throwable = env.exception_occurred()?;
    if **throwable == *JObject::null() {
        Ok(result?)
    } else {
        env.exception_clear()?;

        Err(SignalProtocolError::ApplicationCallbackError(
            fn_name,
            Box::new(ThrownException::new(env, throwable)?),
        )
        .into())
    }
}

macro_rules! jni_bridge_destroy {
    ( $typ:ty as None ) => {};
    ( $typ:ty as $jni_name:ident ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<Java_org_signal_client_internal_Native_ $jni_name _1Destroy>](
                _env: jni::JNIEnv,
                _class: jni::JClass,
                handle: jni::ObjectHandle,
            ) {
                if handle != 0 {
                    let _boxed_value = Box::from_raw(handle as *mut $typ);
                }
            }
        }
    };
    ( $typ:ty ) => {
        paste! {
            jni_bridge_destroy!($typ as $typ);
        }
    };
}

macro_rules! jni_bridge_deserialize {
    ( $typ:ident::$fn:path as None ) => {};
    ( $typ:ident::$fn:path as $jni_name:ident ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<Java_org_signal_client_internal_Native_ $jni_name _1Deserialize>](
                env: jni::JNIEnv,
                _class: jni::JClass,
                data: jni::jbyteArray,
            ) -> jni::ObjectHandle {
                jni::run_ffi_safe(&env, || {
                    let data = env.convert_byte_array(data)?;
                    jni::box_object($typ::$fn(data.as_ref()))
                })
            }
        }
    };
    ( $typ:ident::$fn:path ) => {
        jni_bridge_deserialize!($typ::$fn as $typ);
    };
}

macro_rules! jni_bridge_get_bytearray {
    ( $name:ident($typ:ty) as None => $body:expr ) => {};
    ( $name:ident($typ:ty) as $jni_name:ident => $body:expr ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<Java_org_signal_client_internal_Native_ $jni_name>](
                env: jni::JNIEnv,
                _class: jni::JClass,
                handle: jni::ObjectHandle,
            ) -> jni::jbyteArray {
                expr_as_fn!(inner_get<'a>(
                    obj: &'a $typ
                ) -> Result<impl AsRef<[u8]> + 'a, SignalProtocolError> => $body);
                jni::run_ffi_safe(&env, || {
                    let obj = jni::native_handle_cast::<$typ>(handle)?;
                    jni::to_jbytearray(&env, inner_get(obj))
                })
            }
        }
    };
    ( $name:ident($typ:ty) => $body:expr ) => {
        paste! {
            jni_bridge_get_bytearray!($name($typ) as [<$typ _1 $name:camel>] => $body);
        }
    };
}

macro_rules! jni_bridge_get_optional_bytearray {
    ( $name:ident($typ:ty) as None => $body:expr ) => {};
    ( $name:ident($typ:ty) as $jni_name:ident => $body:expr ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<Java_org_signal_client_internal_Native_ $jni_name>](
                env: jni::JNIEnv,
                _class: jni::JClass,
                handle: jni::ObjectHandle,
            ) -> jni::jbyteArray {
                expr_as_fn!(inner_get<'a>(
                    obj: &'a $typ
                ) -> Result<Option<impl AsRef<[u8]> + 'a>, SignalProtocolError> => $body);
                jni::run_ffi_safe(&env, || {
                    let obj = jni::native_handle_cast::<$typ>(handle)?;
                    match inner_get(obj)? {
                        Some(v) => jni::to_jbytearray(&env, Ok(v)),
                        None => Ok(std::ptr::null_mut()),
                    }
                })
            }
        }
    };
    ( $name:ident($typ:ty) => $body:expr ) => {
        paste! {
            jni_bridge_get_optional_bytearray!($name($typ) as [<$typ _1 $name:camel>] => $body);
        }
    };
}

macro_rules! jni_bridge_get_string {
    ( $name:ident($typ:ty) as None => $body:expr ) => {};
    ( $name:ident($typ:ty) as $jni_name:ident => $body:expr ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<Java_org_signal_client_internal_Native_ $jni_name>](
                env: jni::JNIEnv,
                _class: jni::JClass,
                handle: jni::ObjectHandle,
            ) -> jni::jstring {
                expr_as_fn!(inner_get<'a>(
                    obj: &'a $typ
                ) -> Result<impl Into<jni::JNIString> + 'a, SignalProtocolError> => $body);
                jni::run_ffi_safe(&env, || {
                    let obj = jni::native_handle_cast::<$typ>(handle)?;
                    Ok(env.new_string(inner_get(obj)?)?.into_inner())
                })
            }
        }
    };
    ( $name:ident($typ:ty) => $body:expr ) => {
        paste! {
            jni_bridge_get_string!($name($typ) as [<$typ _1 $name:camel>] => $body);
        }
    };
}

#[macro_export]
macro_rules! jni_bridge_get_optional_string {
    ( $name:ident($typ:ty) as None => $body:expr ) => {};
    ( $name:ident($typ:ty) as $jni_name:ident => $body:expr ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<Java_org_signal_client_internal_Native_ $jni_name>](
                env: jni::JNIEnv,
                _class: jni::JClass,
                handle: jni::ObjectHandle,
            ) -> jni::jstring {
                expr_as_fn!(inner_get<'a>(
                    obj: &'a $typ
                ) -> Result<Option<impl Into<jni::JNIString> + 'a>, SignalProtocolError> => $body);
                jni::run_ffi_safe(&env, || {
                    let obj = jni::native_handle_cast::<$typ>(handle)?;
                    match inner_get(obj)? {
                        Some(s) => Ok(env.new_string(s)?.into_inner()),
                        None => Ok(std::ptr::null_mut())
                    }
                })
            }
        }
    };
    ( $name:ident($typ:ty) => $body:expr ) => {
        paste! {
            jni_bridge_get_optional_string!($name($typ) as [<$typ _1 $name:camel>] => $body);
        }
    };
}
