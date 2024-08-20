//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use jni::objects::{GlobalRef, JClass, JObject, JValue};
use jni::JNIEnv;
use once_cell::sync::OnceCell;

use crate::jni::{BridgeLayerError, HandleJniError};

static CACHED_CLASS_LOADER: OnceCell<GlobalRef> = OnceCell::new();

/// Saves the class loader from the provided `java.lang.Class` instance.
///
/// This is useful on Android where natively-spawned threads use a
/// [`ClassLoader`] that doesn't have access to application-defined classes.
/// Read more [here](https://developer.android.com/training/articles/perf-jni#faq:-why-didnt-findclass-find-my-class).
///
/// [`ClassLoader`]: https://docs.oracle.com/javase/8/docs/api/java/lang/ClassLoader.html
pub fn save_class_loader(
    env: &mut JNIEnv<'_>,
    native_class: &JClass<'_>,
) -> Result<(), BridgeLayerError> {
    let _saved = CACHED_CLASS_LOADER.get_or_try_init(|| {
        super::call_method_checked(
            env,
            native_class,
            "getClassLoader",
            jni_args!(() -> java.lang.ClassLoader),
        )
        .and_then(|class_loader| env.new_global_ref(class_loader).expect_no_exceptions())
    })?;
    Ok(())
}

/// Wrapper type for a Java class name in [binary name] format.
///
/// [binary name]: https://docs.oracle.com/javase/8/docs/api/java/lang/ClassLoader.html#name
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ClassName<'a>(pub &'a str);

impl std::fmt::Display for ClassName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0, f)
    }
}

/// Looks up a class by name.
///
/// Uses the cached class loader, if there is one, or the provided `JNIEnv`. Use
/// this instead of [`JNIEnv::find_class`].
pub fn find_class<'output>(
    env: &mut JNIEnv<'output>,
    class_name: ClassName<'_>,
) -> Result<JClass<'output>, BridgeLayerError> {
    let Some(class_loader) = CACHED_CLASS_LOADER.get() else {
        let jni_name = jni_name_from_binary_name(class_name);
        return real_jni_find_class(env, &jni_name).check_exceptions(env, "FindClass");
    };

    let ClassName(name) = class_name;
    let binary_name = env.new_string(name).check_exceptions(env, "FindClass")?;
    let class = super::call_method_checked(
        env,
        class_loader,
        "loadClass",
        jni_args!((binary_name => java.lang.String) -> java.lang.Class),
    )?;

    Ok(class.into())
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
    name: &str,
) -> Result<JClass<'output>, jni::errors::Error> {
    env.find_class(name)
}

fn jni_name_from_binary_name(ClassName(name): ClassName<'_>) -> String {
    name.replace('.', "/")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn binary_name_conversion() {
        assert_eq!(
            &jni_name_from_binary_name(ClassName("org.signal.libsignal.Native")),
            "org/signal/libsignal/Native"
        );
        assert_eq!(
            &jni_name_from_binary_name(ClassName("org.signal.libsignal.CdsiResponse$Entry")),
            "org/signal/libsignal/CdsiResponse$Entry"
        );
    }
}
