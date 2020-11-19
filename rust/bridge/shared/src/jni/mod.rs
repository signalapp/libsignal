//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::sys::{_jobject, jboolean, jint, jlong, jstring};

use aes_gcm_siv::Error as AesGcmSivError;
use libsignal_protocol_rust::*;

pub(crate) use jni::objects::JClass;
pub(crate) use jni::sys::jbyteArray;
pub(crate) use jni::JNIEnv;

mod error;
pub use error::*;

pub type ObjectHandle = jlong;

pub fn throw_error(env: &JNIEnv, error: SignalJniError) {
    let exception_type = match error {
        SignalJniError::NullHandle => "java/lang/NullPointerException",
        SignalJniError::UnexpectedPanic(_) => "java/lang/AssertionError",
        SignalJniError::BadJniParameter(_) => "java/lang/AssertionError",
        SignalJniError::UnexpectedJniResultType(_, _) => "java/lang/AssertionError",
        SignalJniError::IntegerOverflow(_) => "java/lang/RuntimeException",

        SignalJniError::ExceptionDuringCallback(_) => "java/lang/RuntimeException",

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

        SignalJniError::Signal(SignalProtocolError::UntrustedIdentity(_)) => {
            "org/whispersystems/libsignal/UntrustedIdentityException"
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

    let error_string = match error {
        SignalJniError::Signal(SignalProtocolError::UntrustedIdentity(addr)) => {
            addr.name().to_string()
        }
        e => format!("{}", e),
    };

    let _ = env.throw_new(exception_type, error_string);
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

impl JniDummyValue for *mut _jobject {
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
    ( $typ:ty ) => {
        paste! {
            jni_bridge_destroy!($typ as $typ);
        }
    };
}

macro_rules! jni_bridge_deserialize {
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
