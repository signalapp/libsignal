//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]

#[cfg(not(target_os = "android"))]
use jni::objects::{Auto, JList, JValue};
use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::{jni_sig, jni_str};
use libsignal_bridge::jni::*;
use libsignal_bridge::jni_args;
use libsignal_bridge::net::TokioAsyncContext;
use libsignal_core::try_scoped;
use libsignal_protocol::*;

pub mod logging;

/// Initialize internal data structures.
///
/// Initialization function used to set up internal data structures. This should
/// be called once when the library is first loaded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_signal_libsignal_internal_Native_initializeLibrary<'local>(
    mut env: jni::EnvUnowned<'local>,
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_signal_libsignal_internal_Native_AsyncLoadClass<'local>(
    mut env: jni::EnvUnowned<'local>,
    _class: JClass,
    tokio_context: JObject<'local>,
    class_name: JString,
) -> JObject<'local> {
    struct LoadClassFromName(String);

    impl<'a> ResultTypeInfo<'a> for LoadClassFromName {
        type ResultType = JClass<'a>;

        fn convert_into(
            self,
            env: &mut ::jni::Env<'a>,
        ) -> Result<Self::ResultType, BridgeLayerError> {
            find_class(env, ClassName(&self.0)).check_exceptions(env, "AsyncLoadClass")
        }
    }

    run_ffi_safe(&mut env, |env| {
        let handle = call_method_checked(
            env,
            tokio_context,
            "unsafeNativeHandleWithoutGuard",
            jni_args!(() -> long),
        )?;
        let tokio_context = <&TokioAsyncContext>::borrow(env, &handle)?;
        let class_name = class_name
            .try_to_string(env)
            .check_exceptions(env, "AsyncLoadClass")?;
        run_future_on_runtime(env, &*tokio_context, "AsyncLoadClass", |_cancel| async {
            FutureResultReporter::new(Ok(LoadClassFromName(class_name)), ())
        })
    })
    .into()
}

#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_signal_libsignal_internal_Native_SealedSender_1MultiRecipientParseSentMessage<
    'local,
>(
    mut env: jni::EnvUnowned<'local>,
    _class: JClass,
    data: JByteArray<'local>,
) -> JObject<'local> {
    run_ffi_safe(&mut env, |env| {
        let data_stored = unsafe { data.get_elements(env, jni::objects::ReleaseMode::NoCopyBack) }
            .check_exceptions(env, "MultiRecipientParseSentMessage")?;
        let data_as_slice = zerocopy::IntoBytes::as_bytes(&*data_stored);
        let messages = SealedSenderV2SentMessage::parse(data_as_slice)?;

        let recipient_map_object = new_instance(
            env,
            ClassName("java.util.LinkedHashMap"),
            jni_args!(() -> void),
        )?;

        const RECIPIENT_CLASS_NAME: ClassName<'_> =
            ClassName("org.signal.libsignal.protocol.SealedSenderMultiRecipientMessage$Recipient");
        let (recipient_map, recipient_class, service_id_class) = try_scoped(|| {
            Ok((
                JMap::cast_local(env, recipient_map_object)?,
                find_class(env, RECIPIENT_CLASS_NAME)?,
                find_class(env, ClassName("org.signal.libsignal.protocol.ServiceId"))?,
            ))
        })
        .check_exceptions(env, "MultiRecipientParseSentMessage")?;

        let excluded_recipients_list_object =
            new_instance(env, ClassName("java.util.ArrayList"), jni_args!(() -> void))?;
        let excluded_recipients_list = JList::cast_local(env, excluded_recipients_list_object)
            .check_exceptions(env, "java.util.List")?;

        let parse_from_fixed_width_binary_method = env
            .get_static_method_id(
                &service_id_class,
                jni_str!("parseFromFixedWidthBinary"),
                jni_sig!(([byte]) -> org.signal.libsignal.protocol.ServiceId),
            )
            .check_exceptions(env, "parseFromFixedWidthBinary")?;
        let recipient_class_constructor = env
            .get_method_id(
                &recipient_class,
                jni_str!("<init>"),
                jni_sig!(([byte], [short], int, int) -> void),
            )
            .check_exceptions(env, RECIPIENT_CLASS_NAME.0)?;

        for (service_id, recipient) in &messages.recipients {
            let java_service_id = {
                let java_service_id_bytes = Auto::new(service_id.convert_into(env)?);
                Auto::new(
                    // Use the unchecked method with a cached method identifier
                    // to improve performance.
                    unsafe {
                        call_static_method_unchecked(
                            env,
                            &service_id_class,
                            parse_from_fixed_width_binary_method,
                            jni::signature::ReturnType::Object,
                            &[JValue::from(&java_service_id_bytes).as_jni()],
                        )
                    }
                    .and_then(|v| v.l())
                    .check_exceptions(env, "parseFromFixedWidthBinary")?,
                )
            };

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
            let java_device_ids = Auto::new(
                env.byte_array_from_slice(&device_ids)
                    .check_exceptions(env, "MultiRecipientParseSentMessage")?,
            );
            let java_registration_ids = Auto::new(
                env.new_short_array(registration_ids.len())
                    .check_exceptions(env, "MultiRecipientParseSentMessage")?,
            );
            java_registration_ids
                .set_region(env, 0, &registration_ids)
                .check_exceptions(env, "MultiRecipientParseSentMessage")?;

            let java_recipient = {
                let range = messages.range_for_recipient_key_material(recipient);

                Auto::new(
                    // Use the unchecked method with a cached method identifier
                    // to improve performance.
                    unsafe {
                        new_object_unchecked(
                            env,
                            &recipient_class,
                            recipient_class_constructor,
                            &[
                                JValue::from(&java_device_ids),
                                JValue::from(&java_registration_ids),
                                JValue::Int(range.start.try_into().expect("data too large")),
                                JValue::Int(range.len().try_into().expect("data too large")),
                            ]
                            .map(|j| j.as_jni()),
                        )
                    }
                    .check_exceptions(env, RECIPIENT_CLASS_NAME.0)?,
                )
            };

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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_signal_libsignal_internal_Native_keepAlive(
    _env: jni::EnvUnowned,
    _class: JClass,
    _obj: JObject,
) {
}

#[cfg(target_os = "android")]
fn set_up_rustls_platform_verifier(
    env: &mut jni::Env<'_>,
    class: JClass<'_>,
) -> Result<(), SignalJniError> {
    // The "easy" way of setting up rustls-platform-verifier requires an Android Context object.
    // However, at the time of this writing, the Context was only used to extract a ClassLoader that
    // can find the rustls-platform-verifier Kotlin classes. We can do that with the Native class's
    // loader just as well, so we provide `null` for the Context without worrying about it.
    struct CachedRuntime {
        vm: jni21::JavaVM,
        context: jni21::objects::GlobalRef,
        class_loader: jni21::objects::GlobalRef,
    }
    impl rustls_platform_verifier::android::Runtime for CachedRuntime {
        fn java_vm(&self) -> &jni21::JavaVM {
            &self.vm
        }
        fn context(&self) -> &jni21::objects::GlobalRef {
            &self.context
        }
        fn class_loader(&self) -> &jni21::objects::GlobalRef {
            &self.class_loader
        }
    }

    let class_loader = call_method_checked(
        env,
        class,
        "getClassLoader",
        jni_args!(() -> java.lang.ClassLoader),
    )?;

    let jni21_env = unsafe {
        jni21::JNIEnv::from_raw(env.get_raw().cast()).expect("same underlying representation")
    };

    // This is expected to be one-time setup, so it's okay that we're leaking a bit of configuration info.
    rustls_platform_verifier::android::init_external(Box::leak(Box::new(CachedRuntime {
        vm: jni21_env.get_java_vm().expect("can get VM"),
        context: jni21_env
            .new_global_ref(jni21::objects::JObject::null())
            .expect("can create global ref to null"),
        class_loader: jni21_env
            .new_global_ref(unsafe {
                jni21::objects::JObject::from_raw(class_loader.as_raw().cast())
            })
            .expect("can create global ref to class loader"),
    })));

    Ok(())
}
