//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::OnceLock;

use jni::objects::{Global, JClass, JClassLoader};
use jni::refs::LoaderContext;
use jni::strings::JNIString;

use crate::jni::{BridgeLayerError, HandleJniError};

static CACHED_CLASS_LOADER: OnceLock<Global<JClassLoader<'static>>> = OnceLock::new();

pub fn loader_context() -> Option<LoaderContext<'static, 'static>> {
    CACHED_CLASS_LOADER
        .get()
        .map(|loader| LoaderContext::Loader(loader.as_ref()))
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
    let cl = native_class
        .get_class_loader(env)
        .check_exceptions(env, "save_class_loader")?;
    if cl.is_null() {
        return Err(BridgeLayerError::NullPointer(Some("class loader")));
    }
    let cl = env
        .new_global_ref(cl)
        .check_exceptions(env, "save_class_loader")?;
    if CACHED_CLASS_LOADER.set(cl).is_err() {
        log::warn!("Tried to set the class loader multiple times");
    }
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
    // TODO: remove this allocation, possibly by moving wholesale to bind_java_type!?
    let class_name = JNIString::new(class_name.0);
    loader_context()
        .unwrap_or_default()
        .load_class(env, class_name.as_ref(), true)
}
