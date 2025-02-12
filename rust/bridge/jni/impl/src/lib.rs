//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]

#[cfg(not(target_os = "android"))]
use jni::objects::{AutoLocal, JList, JMap, JValue};
use jni::objects::{JByteArray, JClass, JLongArray, JObject, JString};
use jni::JNIEnv;
use libsignal_bridge::jni::*;
use libsignal_bridge::jni_args;
use libsignal_bridge::net::TokioAsyncContext;
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
        let data = env
            .convert_byte_array(data)
            .check_exceptions(env, "deserialize")?;
        let key = IdentityKeyPair::try_from(data.as_ref())?;

        let public_key_handle = key.identity_key().public_key().convert_into(env)?;
        let private_key_handle = key.private_key().convert_into(env)?;
        let tuple = [public_key_handle, private_key_handle];

        let result = env.new_long_array(2).check_exceptions(env, "deserialize")?;
        env.set_long_array_region(&result, 0, &tuple)
            .check_exceptions(env, "deserialize")?;
        Ok(result)
    })
}

/// Initialize internal data structures.
///
/// Initialization function used to set up internal data structures. This should
/// be called once when the library is first loaded.
#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_libsignal_internal_Native_initializeLibrary<'local>(
    mut env: JNIEnv<'local>,
    class: JClass<'local>,
) {
    run_ffi_safe(&mut env, |env| {
        #[cfg(target_os = "android")]
        save_class_loader(env, &class)?;

        #[cfg(target_os = "android")]
        set_up_rustls_platform_verifier(env, class)?;

        // Silence the unused variable warning on non-Android.
        _ = class;
        _ = env;

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
            find_class(env, ClassName(&self.0)).map_err(Into::into)
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
        let class_name = env
            .get_string(&class_name)
            .check_exceptions(env, "AsyncLoadClass")?
            .into();
        run_future_on_runtime(env, tokio_context, |_cancel| async {
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
            unsafe { env.get_array_elements(&data, jni::objects::ReleaseMode::NoCopyBack) }
                .check_exceptions(env, "MultiRecipientParseSentMessage")?;
        let data_as_slice = <&[u8]>::load_from(&mut data_stored);
        let messages = SealedSenderV2SentMessage::parse(data_as_slice)?;

        let recipient_map_object = new_instance(
            env,
            ClassName("java.util.LinkedHashMap"),
            jni_args!(() -> void),
        )?;
        let recipient_map: JMap = JMap::from_env(env, &recipient_map_object)
            .check_exceptions(env, "MultiRecipientParseSentMessage")?;

        let recipient_class_name =
            ClassName("org.signal.libsignal.protocol.SealedSenderMultiRecipientMessage$Recipient");
        let recipient_class = find_class(env, recipient_class_name)?;
        let service_id_class =
            find_class(env, ClassName("org.signal.libsignal.protocol.ServiceId"))?;

        let excluded_recipients_list_object =
            new_instance(env, ClassName("java.util.ArrayList"), jni_args!(() -> void))?;
        let excluded_recipients_list = JList::from_env(env, &excluded_recipients_list_object)
            .check_exceptions(env, "java.util.List")?;

        for (service_id, recipient) in &messages.recipients {
            let java_service_id_bytes = AutoLocal::new(service_id.convert_into(env)?, env);
            let java_service_id = AutoLocal::new(
                call_static_method_checked(
                    env,
                    &service_id_class,
                    "parseFromFixedWidthBinary",
                    jni_args!((
                        java_service_id_bytes => [byte]
                    ) -> org.signal.libsignal.protocol.ServiceId),
                )?,
                env,
            );

            if recipient.devices.is_empty() {
                excluded_recipients_list
                    .add(env, &java_service_id)
                    .check_exceptions(env, "add")?;
                continue;
            }

            let (device_ids, registration_ids): (Vec<u8>, Vec<i16>) = recipient
                .devices
                .iter()
                .map(|(device_id, registration_id)| {
                    (
                        u8::try_from(u32::from(*device_id)).expect("checked during parsing"),
                        i16::try_from(*registration_id).expect("checked during parsing"),
                    )
                })
                .unzip();
            let java_device_ids = AutoLocal::new(
                env.byte_array_from_slice(&device_ids)
                    .check_exceptions(env, "MultiRecipientParseSentMessage")?,
                env,
            );
            let java_registration_ids = AutoLocal::new(
                env.new_short_array(registration_ids.len().try_into().expect("too many devices"))
                    .check_exceptions(env, "MultiRecipientParseSentMessage")?,
                env,
            );
            env.set_short_array_region(&java_registration_ids, 0, &registration_ids)
                .check_exceptions(env, "MultiRecipientParseSentMessage")?;

            let range = messages.range_for_recipient_key_material(recipient);

            let java_recipient = AutoLocal::new(
                new_object(
                    env,
                    &recipient_class,
                    jni_args!((
                        java_device_ids => [byte],
                        java_registration_ids => [short],
                        range.start.try_into().expect("data too large") => int,
                        range.len().try_into().expect("data too large") => int,
                    ) -> void),
                )
                .check_exceptions(env, recipient_class_name.0)?,
                env,
            );

            recipient_map
                .put(env, &java_service_id, &java_recipient)
                .check_exceptions(env, "put")?;
        }

        let offset_of_shared_bytes = messages.offset_of_shared_bytes();

        Ok(new_instance(
            env,
            ClassName("org.signal.libsignal.protocol.SealedSenderMultiRecipientMessage"),
            jni_args!((
                data => [byte],
                recipient_map => java.util.Map,
                excluded_recipients_list => java.util.List,
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
    struct CachedRuntime {
        vm: jni::JavaVM,
        context: jni::objects::GlobalRef,
        class_loader: jni::objects::GlobalRef,
    }
    impl rustls_platform_verifier::android::Runtime for CachedRuntime {
        fn java_vm(&self) -> &jni::JavaVM {
            &self.vm
        }
        fn context(&self) -> &jni::objects::GlobalRef {
            &self.context
        }
        fn class_loader(&self) -> &jni::objects::GlobalRef {
            &self.class_loader
        }
    }

    let class_loader = call_method_checked(
        env,
        class,
        "getClassLoader",
        jni_args!(() -> java.lang.ClassLoader),
    )?;

    // This is expected to be one-time setup, so it's okay that we're leaking a bit of configuration info.
    rustls_platform_verifier::android::init_external(Box::leak(Box::new(CachedRuntime {
        vm: env.get_java_vm().expect("can get VM"),
        context: env
            .new_global_ref(JObject::null())
            .expect("can create global ref to null"),
        class_loader: env
            .new_global_ref(class_loader)
            .expect("can create global ref to class loader"),
    })));

    Ok(())
}
