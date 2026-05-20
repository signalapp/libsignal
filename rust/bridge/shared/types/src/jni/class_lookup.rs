//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ffi::CString;

use jni::objects::{Global, JClass, JMethodID, JObject, JValue};
use jni::strings::JNIStr;
use jni::{jni_sig, jni_str};
use libsignal_core::try_scoped;
use once_cell::sync::OnceCell;

use crate::jni::{BridgeLayerError, HandleJniError};

static CACHED_CLASS_LOADER: OnceCell<CachedLoader> = OnceCell::new();

struct CachedLoader {
    /// A `java.lang.ClassLoader`.
    class_loader: Global<JObject<'static>>,
    /// JNI reference to `ClassLoader.loadClass`.
    load_class_method: JMethodID,
}

/// Saves the class loader from the provided `java.lang.Class` instance.
///
/// This is useful on Android where natively-spawned threads use a
/// [`ClassLoader`] that doesn't have access to application-defined classes.
/// Read more [here](https://developer.android.com/training/articles/perf-jni#faq:-why-didnt-findclass-find-my-class).
///
/// [`ClassLoader`]: https://docs.oracle.com/javase/8/docs/api/java/lang/ClassLoader.html
pub fn save_class_loader(
    env: &mut jni::Env<'_>,
    native_class: &JClass<'_>,
) -> Result<(), BridgeLayerError> {
    let _saved = CACHED_CLASS_LOADER.get_or_try_init(|| {
        let loader = super::call_method_checked(
            env,
            native_class,
            "getClassLoader",
            jni_args!(() -> java.lang.ClassLoader),
        )?;

        try_scoped(|| {
            let loader_class = env.get_object_class(&loader)?;
            let load_class_method = env.get_method_id(
                loader_class,
                jni_str!("loadClass"),
                jni_sig!((java.lang.String) -> java.lang.Class),
            )?;
            let class_loader = env.new_global_ref(loader)?;
            Ok(CachedLoader {
                class_loader,
                load_class_method,
            })
        })
        .expect_no_exceptions()
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
/// Uses the cached class loader, if there is one, or the provided `jni::Env`. Use
/// this instead of [`jni::Env::find_class`].
pub fn find_class<'output>(
    env: &mut jni::Env<'output>,
    class_name: ClassName<'_>,
) -> jni::errors::Result<JClass<'output>> {
    // TODO: replace this with jni::refs::LoaderContext,
    // which handles the cached loader and "default" modes more uniformly.
    let Some(class_loader) = CACHED_CLASS_LOADER.get() else {
        let jni_name = jni_name_from_binary_name(class_name);
        return real_jni_find_class(env, JNIStr::from_cstr(&jni_name).expect("ASCII"));
    };

    // TODO: replace this with a (validated) JNI string.
    let binary_name = jni::objects::JString::from_str(env, class_name.0)?;

    let CachedLoader {
        class_loader,
        load_class_method,
    } = class_loader;

    // SAFETY: the method was looked up for the loader and the arguments and
    // return type passed in here match the signature it was looked up with.
    let class = unsafe {
        // There isn't a helper for this (yet), but even if there were we
        // probably wouldn't want to use it. Doing so would lead to recursion in
        // some builds where the helper would call back into this function.
        #[allow(clippy::disallowed_methods)]
        env.call_method_unchecked(
            class_loader,
            load_class_method,
            jni::signature::ReturnType::Object,
            &[JValue::from(&binary_name).as_jni()],
        )
    }?
    .l()?;

    env.cast_local::<JClass>(class)
}

/// Equivalent to [`jni::Env::find_class`].
///
/// That function is marked as disallowed because its behavior is different on
/// Android depending on what thread it is called from. In most cases, the
/// [`find_class`] function in this module should be used instead. However,
/// since the real thing is needed to implement that helper, this function
/// exists to provide a narrowly-scoped `#[allow]`ed exception to the rule.
#[expect(clippy::disallowed_methods)]
fn real_jni_find_class<'output>(
    env: &mut jni::Env<'output>,
    name: &JNIStr,
) -> Result<JClass<'output>, jni::errors::Error> {
    env.find_class(name)
}

/// Equivalent to [`jni::Env::find_class`], but only intended for use with primitive arrays (specified
/// using [`jni_sig`]).
///
/// Use [`find_class`] for actual classes, and, uh, nothing has been built yet for arrays of
/// classes.
#[inline]
pub fn find_primitive_array_class<'output>(
    env: &mut jni::Env<'output>,
    name: &JNIStr,
) -> Result<JClass<'output>, jni::errors::Error> {
    real_jni_find_class(env, name)
}

fn jni_name_from_binary_name(name: ClassName<'_>) -> CString {
    let mut name_bytes = name.0.as_bytes().to_vec();
    for next in &mut name_bytes[..] {
        if *next == b'.' {
            *next = b'/'
        }
    }
    name_bytes.push(0);
    CString::from_vec_with_nul(name_bytes).expect("no embedded NUL")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn binary_name_conversion() {
        assert_eq!(
            &jni_name_from_binary_name(ClassName("org.signal.libsignal.Native"))[..],
            c"org/signal/libsignal/Native"
        );
        assert_eq!(
            &jni_name_from_binary_name(ClassName("org.signal.libsignal.CdsiResponse$Entry"))[..],
            c"org/signal/libsignal/CdsiResponse$Entry"
        );
    }
}
