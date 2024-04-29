//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]

use jni::objects::{JByteArray, JClass, JLongArray, JObject, JString};
#[cfg(not(target_os = "android"))]
use jni::objects::{JMap, JValue};
use jni::JNIEnv;

use libsignal_bridge::jni::*;
use libsignal_bridge::net::TokioAsyncContext;
use libsignal_bridge::{jni_args, jni_class_name};
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

/// Preload classes used in natively-spawned threads.
///
/// This is useful on Android where natively-spawned threads use a
/// [`ClassLoader`] that doesn't have access to application-defined classes.
/// Read more [here](https://developer.android.com/training/articles/perf-jni#faq:-why-didnt-findclass-find-my-class).
///
/// [`ClassLoader`]: https://docs.oracle.com/javase/8/docs/api/java/lang/ClassLoader.html
#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_libsignal_internal_Native_preloadClasses<'local>(
    mut env: JNIEnv<'local>,
    class: JClass<'local>,
) {
    run_ffi_safe(&mut env, |env| {
        preload_classes(env)?;

        #[cfg(target_os = "android")]
        set_up_rustls_platform_verifier(env, class)?;
        // Silence the unused variable warning on non-Android.
        _ = class;

        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_libsignal_internal_Native_AsyncLoadClass<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    tokio_context: JObject<'local>,
    class_name: JString,
) -> JObject<'local> {
    struct LoadClassFromName(String);

    impl<'a> ResultTypeInfo<'a> for LoadClassFromName {
        type ResultType = JClass<'a>;

        fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
            find_class(env, &self.0).map_err(Into::into)
        }
    }

    run_ffi_safe(&mut env, |env| {
        let handle = call_method_checked(
            env,
            tokio_context,
            "unsafeNativeHandleWithoutGuard",
            jni_args!(() -> long),
        )?;
        let tokio_context = <&TokioAsyncContext>::convert_from(env, &handle)?;
        let class_name = env.get_string(&class_name)?.into();
        run_future_on_runtime(env, tokio_context, async {
            FutureResultReporter::new(Ok(LoadClassFromName(class_name)), ())
        })
    })
    .into()
}

#[cfg(not(target_os = "android"))]
#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_libsignal_internal_Native_SealedSender_1MultiRecipientParseSentMessage<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    data: JByteArray<'local>,
) -> JObject<'local> {
    run_ffi_safe(&mut env, |env| {
        let mut data_stored =
            unsafe { env.get_array_elements(&data, jni::objects::ReleaseMode::NoCopyBack)? };
        let data_as_slice = <&[u8]>::load_from(&mut data_stored);
        let messages = SealedSenderV2SentMessage::parse(data_as_slice)?;

        let recipient_map_object = new_object(
            env,
            jni_class_name!(java.util.LinkedHashMap),
            jni_args!(() -> void),
        )?;
        let recipient_map: JMap = JMap::from_env(env, &recipient_map_object)?;

        const NUMBER_OF_OBJECTS_PER_RECIPIENT: usize = 5; // ServiceId + service ID bytes + Recipient + array of device IDs + array of registration IDs
        let excluded_recipients_array = env.with_local_frame_returning_local(
            (messages.recipients.len() * NUMBER_OF_OBJECTS_PER_RECIPIENT)
                .try_into()
                .expect("too many recipients"),
            |env| -> SignalJniResult<_> {
                let recipient_class = find_class(
                    env,
                    jni_class_name!(
                        org.signal
                            .libsignal
                            .protocol
                            .SealedSenderMultiRecipientMessage
                            ::Recipient
                    ),
                )?;
                let service_id_class = find_class(
                    env,
                    jni_class_name!(org.signal.libsignal.protocol.ServiceId),
                )?;

                let mut excluded_recipient_java_service_ids = vec![];

                for (service_id, recipient) in &messages.recipients {
                    let java_service_id_bytes = service_id.convert_into(env)?;
                    let java_service_id = call_static_method_checked(
                        env,
                        &service_id_class,
                        "parseFromFixedWidthBinary",
                        jni_args!((
                            java_service_id_bytes => [byte]
                        ) -> org.signal.libsignal.protocol.ServiceId),
                    )?;

                    if recipient.devices.is_empty() {
                        excluded_recipient_java_service_ids.push(java_service_id);
                        continue;
                    }

                    let (device_ids, registration_ids): (Vec<u8>, Vec<i16>) = recipient
                        .devices
                        .iter()
                        .map(|(device_id, registration_id)| {
                            (
                                u8::try_from(u32::from(*device_id))
                                    .expect("checked during parsing"),
                                i16::try_from(*registration_id).expect("checked during parsing"),
                            )
                        })
                        .unzip();
                    let java_device_ids = env.byte_array_from_slice(&device_ids)?;
                    let java_registration_ids = env.new_short_array(
                        registration_ids.len().try_into().expect("too many devices"),
                    )?;
                    env.set_short_array_region(&java_registration_ids, 0, &registration_ids)?;

                    let range = messages.range_for_recipient_key_material(recipient);

                    let java_recipient = new_object(
                        env,
                        &recipient_class,
                        jni_args!((
                            java_device_ids => [byte],
                            java_registration_ids => [short],
                            range.start.try_into().expect("data too large") => int,
                            range.len().try_into().expect("data too large") => int,
                        ) -> void),
                    )?;

                    recipient_map.put(env, &java_service_id, &java_recipient)?;
                }

                let excluded_recipients_array = env.new_object_array(
                    excluded_recipient_java_service_ids
                        .len()
                        .try_into()
                        .expect("too many excluded recipients"),
                    jni_class_name!(org.signal.libsignal.protocol.ServiceId),
                    JObject::null(),
                )?;
                for (java_excluded_recipient, i) in
                    excluded_recipient_java_service_ids.into_iter().zip(0i32..)
                {
                    env.set_object_array_element(
                        &excluded_recipients_array,
                        i,
                        java_excluded_recipient,
                    )?;
                }
                Ok(excluded_recipients_array.into())
            },
        )?;

        let offset_of_shared_bytes = messages.offset_of_shared_bytes();

        Ok(new_object(
            env,
            jni_class_name!(
                org.signal
                    .libsignal
                    .protocol
                    .SealedSenderMultiRecipientMessage
            ),
            jni_args!((
                data => [byte],
                recipient_map => java.util.Map,
                excluded_recipients_array => [org.signal.libsignal.protocol.ServiceId],
                offset_of_shared_bytes.try_into().expect("data too large") => int,
            ) -> void),
        )?)
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

#[cfg(target_os = "android")]
fn set_up_rustls_platform_verifier(
    env: &mut JNIEnv<'_>,
    class: JClass<'_>,
) -> Result<(), SignalJniError> {
    // The "easy" way of setting up rustls-platform-verifier requires an Android Context object.
    // However, at the time of this writing, the Context was only used to extract a ClassLoader that
    // can find the rustls-platform-verifier Kotlin classes. We can do that with the Native class's
    // loader just as well, so we provide `null` for the Context without worrying about it.
    // (It *is* unfortunate that they're still using jni 0.19 though.
    // https://github.com/rustls/rustls-platform-verifier/issues/22)
    struct CachedRuntime {
        vm: jni19::JavaVM,
        context: jni19::objects::GlobalRef,
        class_loader: jni19::objects::GlobalRef,
    }
    impl rustls_platform_verifier::android::Runtime for CachedRuntime {
        fn java_vm(&self) -> &jni19::JavaVM {
            &self.vm
        }
        fn context(&self) -> &jni19::objects::GlobalRef {
            &self.context
        }
        fn class_loader(&self) -> &jni19::objects::GlobalRef {
            &self.class_loader
        }
    }

    let class_loader = call_method_checked(
        env,
        class,
        "getClassLoader",
        jni_args!(() -> java.lang.ClassLoader),
    )?;

    // JNIEnv, old or new, is a wrapper around a raw table (C struct) of function pointers.
    // So it's safe to convert from the old one to the new one.
    // Note that we can't propagate the errors normally because they are jni19 Errors,
    // but if there ever *are* any errors we are running inside run_ffi_safe anyway.
    let jni19_env =
        unsafe { jni19::JNIEnv::from_raw(env.get_raw() as *mut _) }.expect("valid JNIEnv");
    // This is expected to be one-time setup, so it's okay that we're leaking a bit of configuration info.
    rustls_platform_verifier::android::init_external(Box::leak(Box::new(CachedRuntime {
        vm: jni19_env.get_java_vm().expect("can get VM"),
        context: jni19_env
            .new_global_ref(std::ptr::null_mut())
            .expect("can create global ref to null"),
        class_loader: jni19_env
            .new_global_ref(class_loader.as_raw())
            .expect("can create global ref to class loader"),
    })));

    Ok(())
}
