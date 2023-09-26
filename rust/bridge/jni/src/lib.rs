//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]

use jni::objects::{JByteArray, JClass, JLongArray, JObject};
use jni::JNIEnv;
use std::convert::TryFrom;

use libsignal_bridge::jni::*;
use libsignal_protocol::*;

pub mod logging;

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_libsignal_internal_Native_IdentityKeyPair_1Deserialize<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    data: JByteArray,
) -> JLongArray<'local> {
    run_ffi_safe(&mut env, |env| {
        let data = env.convert_byte_array(data)?;
        let key = IdentityKeyPair::try_from(data.as_ref())?;

        let public_key_handle = key.identity_key().public_key().convert_into(env)?;
        let private_key_handle = key.private_key().convert_into(env)?;
        let tuple = [public_key_handle, private_key_handle];

        let result = env.new_long_array(2)?;
        env.set_long_array_region(&result, 0, &tuple)?;
        Ok(result)
    })
}

/// An optimization barrier / guard against garbage collection.
///
/// cbindgen:ignore
#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_libsignal_internal_Native_keepAlive(
    _env: JNIEnv,
    _class: JClass,
    _obj: JObject,
) {
}

// These APIs are only useful for tests.
// To save on code size, we omit them when building for Android.
#[cfg(not(target_os = "android"))]
mod test_apis {
    use super::*;

    use jni::sys::jint;
    use libsignal_bridge::{jni_args, jni_class_name};

    #[no_mangle]
    pub unsafe extern "C" fn Java_org_signal_libsignal_internal_Native_Future_1success<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass,
    ) -> JavaFuture<'local, jint> {
        run_ffi_safe(&mut env, |env| {
            let future = new_object(
                env,
                jni_class_name!(org.signal.libsignal.internal.CompletableFuture),
                jni_args!(() -> void),
            )?;
            let completer = FutureCompleter::new(env, &future)?;
            std::thread::spawn(move || completer.complete(42));
            Ok(future.into())
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_org_signal_libsignal_internal_Native_Future_1failure<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass,
    ) -> JavaFuture<'local, jint> {
        run_ffi_safe(&mut env, |env| {
            let future = new_object(
                env,
                jni_class_name!(org.signal.libsignal.internal.CompletableFuture),
                jni_args!(() -> void),
            )?;
            let completer = FutureCompleter::new(env, &future)?;
            std::thread::spawn(move || {
                completer.complete(Err::<(), _>(SignalProtocolError::InvalidArgument(
                    "failure".to_string(),
                )))
            });
            Ok(future.into())
        })
    }
}
