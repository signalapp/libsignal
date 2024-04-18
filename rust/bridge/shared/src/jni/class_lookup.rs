//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::collections::HashMap;

use jni::objects::{AutoLocal, GlobalRef, JClass, JObject, JThrowable};
use jni::JNIEnv;
use once_cell::sync::OnceCell;

use crate::jni::{BridgeLayerError, ThrownException};

static PRELOADED_CLASSES: OnceCell<HashMap<&'static str, GlobalRef>> = OnceCell::new();

const PRELOADED_CLASS_NAMES: &[&str] = &[
    jni_class_name!(org.signal.libsignal.attest.AttestationFailedException),
    jni_class_name!(org.signal.libsignal.net.CdsiInvalidTokenException),
    jni_class_name!(org.signal.libsignal.net.CdsiLookupResponse),
    jni_class_name!(org.signal.libsignal.net.CdsiLookupResponse::Entry),
    jni_class_name!(org.signal.libsignal.net.CdsiProtocolException),
    jni_class_name!(org.signal.libsignal.net.ChatService),
    jni_class_name!(org.signal.libsignal.net.ChatService::DebugInfo),
    jni_class_name!(org.signal.libsignal.net.ChatService::Response),
    jni_class_name!(org.signal.libsignal.net.ChatService::ResponseAndDebugInfo),
    jni_class_name!(org.signal.libsignal.net.ChatServiceException),
    jni_class_name!(org.signal.libsignal.net.ChatServiceInactiveException),
    jni_class_name!(org.signal.libsignal.net.NetworkException),
    jni_class_name!(org.signal.libsignal.net.RetryLaterException),
    jni_class_name!(
        org.signal
            .libsignal
            .sgxsession
            .SgxCommunicationFailureException
    ),
    jni_class_name!(org.signal.libsignal.svr.DataMissingException),
    jni_class_name!(org.signal.libsignal.svr.RestoreFailedException),
    jni_class_name!(org.signal.libsignal.svr.SvrException),
    #[cfg(feature = "testing-fns")]
    jni_class_name!(org.signal.libsignal.internal.TestingException),
];

/// Preloads some classes from the provided [`JNIEnv`].
///
/// Uses [`JNIEnv::find_class`] to cache some classes in a static variable for
/// later. These cached class instances can later be retrieved with
/// [`find_class`].
pub fn preload_classes(env: &mut JNIEnv<'_>) -> Result<(), BridgeLayerError> {
    let _saved = PRELOADED_CLASSES.get_or_try_init(|| {
        let no_class_found_exceptions = {
            let first = real_jni_find_class(env, jni_class_name!(java.lang.NoClassDefFoundError))?;
            let second =
                real_jni_find_class(env, jni_class_name!(java.lang.ClassNotFoundException))?;
            [first, second]
        };

        let is_not_found_exception =
            |throwable: &JThrowable<'_>, env: &JNIEnv<'_>| -> jni::errors::Result<bool> {
                for no_class_found in &no_class_found_exceptions {
                    if env.is_same_object(env.get_object_class(throwable)?, no_class_found)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            };

        PRELOADED_CLASS_NAMES
            .iter()
            .map(|name| {
                let find_class_result =
                    real_jni_find_class(env, name).map(|c| AutoLocal::new(c, env));
                let throwable = AutoLocal::new(env.exception_occurred()?, env);
                let class = if throwable.is_null() {
                    find_class_result?
                } else {
                    env.exception_clear()?;

                    if !is_not_found_exception(&throwable, env)? {
                        return Err(BridgeLayerError::CallbackException(
                            "FindClass",
                            ThrownException::new(env, throwable)?,
                        ));
                    }

                    // Ignore failures caused by nonexistent classes. This
                    // allows the same native library to be used with JAR files
                    // that contain different subsets of classes.
                    AutoLocal::new(JObject::null().into(), env)
                };
                let global_ref = env.new_global_ref(class)?;
                Ok((*name, global_ref))
            })
            .collect::<Result<HashMap<_, _>, BridgeLayerError>>()
    })?;

    Ok(())
}

/// Looks up a class by name.
///
/// Checks the set of preloaded classes first to prevent lookup errors caused by
/// the class path differing for different threads.  Use this instead of
/// [`JNIEnv::find_class`].
pub fn find_class<'output>(
    env: &mut JNIEnv<'output>,
    name: &'static str,
) -> Result<JClass<'output>, jni::errors::Error> {
    match get_preloaded_class(env, name)? {
        Some(c) => Ok(c),
        None => real_jni_find_class(env, name),
    }
}

/// Loads a previously cached class.
///
/// Looks up the given class name saved by [`preload_classes`], if there was
/// one. Returns `Ok(None)` otherwise.
///
/// This is useful on platforms like Android where JVM-spawned threads have
/// access to application-defined classes but native threads (including Tokio
/// runtime threads) do not. A class object cached from a JVM-spawned thread can
/// be used by natively-spawned threads to access application-defined types.
fn get_preloaded_class<'output>(
    env: &mut JNIEnv<'output>,
    name: &'static str,
) -> Result<Option<JClass<'output>>, jni::errors::Error> {
    let class = PRELOADED_CLASSES
        .get()
        .expect("Java classes were not preloaded")
        .get(&name);

    let local_ref = class.map(|class| env.new_local_ref(class)).transpose()?;

    Ok(local_ref.map(Into::into))
}

/// Equivalent to [`JNIEnv::find_class`].
///
/// That function is marked as disallowed because its behavior is different on
/// Android depending on what thread it is called from. In most cases, the
/// [`find_class`] function in this module should be used instead. However,
/// since the real thing is needed to implement that helper, this function
/// exists to provide a narrowly-scoped `#[allow]`ed exception to the rule.
#[allow(clippy::disallowed_methods)]
fn real_jni_find_class<'output>(
    env: &mut JNIEnv<'output>,
    name: &'static str,
) -> Result<JClass<'output>, jni::errors::Error> {
    env.find_class(name)
}
