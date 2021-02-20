//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::objects::{JObject, JThrowable, JValue};
use jni::sys::jobject;

use aes_gcm_siv::Error as AesGcmSivError;
use libsignal_protocol::*;
use std::convert::TryFrom;
use std::error::Error;

pub(crate) use jni::objects::{JClass, JString};
pub(crate) use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
pub(crate) use jni::JNIEnv;

#[macro_use]
mod convert;
pub(crate) use convert::*;

mod error;
pub use error::*;

mod storage;
pub use storage::*;

pub use crate::support::expect_ready;

pub type ObjectHandle = jlong;

fn throw_error(env: &JNIEnv, error: SignalJniError) {
    // Handle special cases first.
    let error = match error {
        SignalJniError::Signal(SignalProtocolError::ApplicationCallbackError(
            callback,
            exception,
        )) => {
            // The usual way to write this code would be to match on the result of Error::downcast.
            // However, the "failure" result, which is intended to return the original type back,
            // only supports Send and Sync as additional traits. For anything else, we have to test first.
            if Error::is::<ThrownException>(&*exception) {
                let exception =
                    Error::downcast::<ThrownException>(exception).expect("just checked");
                if let Err(e) = env.throw(exception.as_obj()) {
                    log::error!("failed to rethrow exception from {}: {}", callback, e);
                }
                return;
            }

            // Fall through to generic handling below.
            SignalJniError::Signal(SignalProtocolError::ApplicationCallbackError(
                callback, exception,
            ))
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

        SignalJniError::Signal(SignalProtocolError::FingerprintVersionMismatch(theirs, ours)) => {
            let throwable = env.new_object(
                "org/whispersystems/libsignal/fingerprint/FingerprintVersionMismatchException",
                "(II)V",
                &[JValue::from(theirs as jint), JValue::from(ours as jint)],
            );

            match throwable {
                Err(e) => log::error!("failed to create exception for {}: {}", error, e),
                Ok(throwable) => {
                    let result = env.throw(JThrowable::from(throwable));
                    if let Err(e) = result {
                        log::error!("failed to throw exception for {}: {}", error, e);
                    }
                }
            }
            return;
        }

        e => e,
    };

    let exception_type = match error {
        SignalJniError::NullHandle => "java/lang/NullPointerException",

        SignalJniError::Signal(SignalProtocolError::InvalidState(_, _))
        | SignalJniError::Signal(SignalProtocolError::NoSenderKeyState)
        | SignalJniError::Signal(SignalProtocolError::InvalidSessionStructure) => {
            "java/lang/IllegalStateException"
        }

        SignalJniError::Signal(SignalProtocolError::InvalidArgument(_))
        | SignalJniError::AesGcmSiv(AesGcmSivError::InvalidInputSize)
        | SignalJniError::AesGcmSiv(AesGcmSivError::InvalidNonceSize) => {
            "java/lang/IllegalArgumentException"
        }

        SignalJniError::UnexpectedPanic(_)
        | SignalJniError::BadJniParameter(_)
        | SignalJniError::UnexpectedJniResultType(_, _) => "java/lang/AssertionError",

        SignalJniError::IntegerOverflow(_)
        | SignalJniError::Jni(_)
        | SignalJniError::Signal(SignalProtocolError::ApplicationCallbackError(_, _))
        | SignalJniError::Signal(SignalProtocolError::FfiBindingError(_))
        | SignalJniError::Signal(SignalProtocolError::InternalError(_))
        | SignalJniError::Signal(SignalProtocolError::InvalidChainKeyLength(_))
        | SignalJniError::Signal(SignalProtocolError::InvalidCipherCryptographicParameters(_, _))
        | SignalJniError::Signal(SignalProtocolError::InvalidMacKeyLength(_))
        | SignalJniError::Signal(SignalProtocolError::InvalidRootKeyLength(_))
        | SignalJniError::Signal(SignalProtocolError::ProtobufEncodingError(_)) => {
            "java/lang/RuntimeException"
        }

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

        SignalJniError::Signal(SignalProtocolError::SessionNotFound(_)) => {
            "org/whispersystems/libsignal/NoSessionException"
        }

        SignalJniError::Signal(SignalProtocolError::InvalidMessage(_))
        | SignalJniError::Signal(SignalProtocolError::CiphertextMessageTooShort(_))
        | SignalJniError::Signal(SignalProtocolError::InvalidCiphertext)
        | SignalJniError::Signal(SignalProtocolError::InvalidProtobufEncoding)
        | SignalJniError::Signal(SignalProtocolError::ProtobufDecodingError(_))
        | SignalJniError::Signal(SignalProtocolError::InvalidSealedSenderMessage(_))
        | SignalJniError::AesGcmSiv(AesGcmSivError::InvalidTag) => {
            "org/whispersystems/libsignal/InvalidMessageException"
        }

        SignalJniError::Signal(SignalProtocolError::UnrecognizedCiphertextVersion(_))
        | SignalJniError::Signal(SignalProtocolError::UnrecognizedMessageVersion(_))
        | SignalJniError::Signal(SignalProtocolError::UnknownSealedSenderVersion(_)) => {
            "org/whispersystems/libsignal/InvalidVersionException"
        }

        SignalJniError::Signal(SignalProtocolError::LegacyCiphertextVersion(_)) => {
            "org/whispersystems/libsignal/LegacyMessageException"
        }

        SignalJniError::Signal(SignalProtocolError::SealedSenderSelfSend) => {
            "org/signal/libsignal/metadata/SelfSendException"
        }

        SignalJniError::Signal(SignalProtocolError::UntrustedIdentity(_))
        | SignalJniError::Signal(SignalProtocolError::FingerprintVersionMismatch(_, _)) => {
            unreachable!("already handled in prior match")
        }

        SignalJniError::Signal(SignalProtocolError::FingerprintIdentifierMismatch)
        | SignalJniError::Signal(SignalProtocolError::FingerprintParsingError) => {
            "org/whispersystems/libsignal/fingerprint/FingerprintParsingException"
        }
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

pub fn jobject_from_native_handle<'a>(
    env: &'a JNIEnv,
    class_name: &str,
    boxed_handle: ObjectHandle,
) -> Result<JObject<'a>, SignalJniError> {
    let class_type = env.find_class(class_name)?;
    let ctor_sig = "(J)V";
    let ctor_args = [JValue::from(boxed_handle)];
    Ok(env.new_object(class_type, ctor_sig, &ctor_args)?)
}

pub fn jobject_from_serialized<'a>(
    env: &'a JNIEnv,
    class_name: &str,
    serialized: &[u8],
) -> Result<JObject<'a>, SignalJniError> {
    let class_type = env.find_class(class_name)?;
    let ctor_sig = "([B)V";
    let ctor_args = [JValue::from(to_jbytearray(env, Ok(serialized))?)];
    Ok(env.new_object(class_type, ctor_sig, &ctor_args)?)
}

pub fn check_jobject_type(
    env: &JNIEnv,
    obj: JObject,
    class_name: &'static str,
) -> Result<(), SignalJniError> {
    if obj.is_null() {
        return Err(SignalJniError::NullHandle);
    }

    let class = env.find_class(class_name)?;

    if !env.is_instance_of(obj, class)? {
        return Err(SignalJniError::BadJniParameter(class_name));
    }

    Ok(())
}

pub fn get_object_with_native_handle<T: 'static + Clone>(
    env: &JNIEnv,
    store_obj: JObject,
    callback_args: &[JValue],
    callback_sig: &'static str,
    callback_fn: &'static str,
) -> Result<Option<T>, SignalJniError> {
    let rvalue = call_method_checked(env, store_obj, callback_fn, callback_sig, &callback_args)?;

    let obj = match rvalue {
        JValue::Object(o) => *o,
        _ => {
            return Err(SignalJniError::UnexpectedJniResultType(
                callback_fn,
                rvalue.type_name(),
            ))
        }
    };

    if obj.is_null() {
        return Ok(None);
    }

    let handle = call_method_checked(env, obj, "nativeHandle", "()J", &[])?;
    match handle {
        JValue::Long(handle) => {
            if handle == 0 {
                return Ok(None);
            }
            let object = unsafe { native_handle_cast::<T>(handle)? };
            Ok(Some(object.clone()))
        }
        _ => Err(SignalJniError::UnexpectedJniResultType(
            "nativeHandle",
            handle.type_name(),
        )),
    }
}

pub fn get_object_with_serialization(
    env: &JNIEnv,
    store_obj: JObject,
    callback_args: &[JValue],
    callback_sig: &'static str,
    callback_fn: &'static str,
) -> Result<Option<Vec<u8>>, SignalJniError> {
    let rvalue = call_method_checked(env, store_obj, callback_fn, callback_sig, &callback_args)?;

    let obj = match rvalue {
        JValue::Object(o) => *o,
        _ => {
            return Err(SignalJniError::UnexpectedJniResultType(
                callback_fn,
                rvalue.type_name(),
            ))
        }
    };

    if obj.is_null() {
        return Ok(None);
    }

    let bytes = call_method_checked(env, obj, "serialize", "()[B", &[])?;

    match bytes {
        JValue::Object(o) => Ok(Some(env.convert_byte_array(*o)?)),
        _ => Err(SignalJniError::UnexpectedJniResultType(
            "serialize",
            bytes.type_name(),
        )),
    }
}

macro_rules! jni_bridge_destroy {
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
}

macro_rules! jni_bridge_deserialize {
    ( $typ:ident::$fn:path as false ) => {};
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
    ( $name:ident($typ:ty) as false => $body:expr ) => {};
    ( $name:ident($typ:ty) as $jni_name:tt => $body:expr ) => {
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
    ( $name:ident($typ:ty) as false => $body:expr ) => {};
    ( $name:ident($typ:ty) as $jni_name:tt => $body:expr ) => {
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
