//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::objects::{JClass, JMethodID, JObject, JStaticMethodID, JValueOwned};
use jni::strings::JNIString;

use crate::jni::{BridgeLayerError, HandleJniError as _, JniArgs};

/// Calls a method and translates any thrown exceptions to
/// [`BridgeLayerError::CallbackException`].
///
/// Wraps [`jni::Env::call_method`].
/// The result must have the correct type, or [`BridgeLayerError::UnexpectedJniResultType`] will be
/// returned instead.
pub fn call_method_checked<
    'input,
    'output,
    O: AsRef<JObject<'input>>,
    R: TryFrom<JValueOwned<'output>>,
    const LEN: usize,
>(
    env: &mut jni::Env<'output>,
    obj: O,
    fn_name: &'static str,
    args: JniArgs<R, LEN>,
) -> Result<R, BridgeLayerError> {
    // TODO: If we use a pre-validated CStr for fn_name, we can avoid this copy.
    let jni_fn_name = JNIString::new(fn_name);

    if cfg!(feature = "jni-invoke-annotated") {
        check_annotations::called_method(env, obj.as_ref(), &jni_fn_name, &args.sig)
            .check_exceptions(env, fn_name)?
    }

    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    #[allow(clippy::disallowed_methods)]
    let result = env.call_method(obj, &jni_fn_name, args.sig, &args.args);
    check_exceptions_and_convert_result(env, fn_name, result)
}

/// Calls a method and translates any thrown exceptions to
/// [`BridgeLayerError::CallbackException`].
///
/// Wraps [`jni::Env::call_static_method`].
/// The result must have the correct type, or [`BridgeLayerError::UnexpectedJniResultType`] will be
/// returned instead.
pub fn call_static_method_checked<
    'input,
    'output,
    C: jni::descriptors::Desc<'output, JClass<'input>>,
    R: TryFrom<JValueOwned<'output>>,
    const LEN: usize,
>(
    env: &mut jni::Env<'output>,
    cls: C,
    fn_name: &'static str,
    args: JniArgs<R, LEN>,
) -> Result<R, BridgeLayerError> {
    // TODO: If we use a pre-validated CStr for fn_name, we can avoid this copy.
    let jni_fn_name = JNIString::new(fn_name);

    let cls = cls.lookup(env).check_exceptions(env, fn_name)?;
    if cfg!(feature = "jni-invoke-annotated") {
        check_annotations::static_method(env, cls.as_ref(), &jni_fn_name, &args.sig)
            .check_exceptions(env, fn_name)?;
    }

    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    #[allow(clippy::disallowed_methods)]
    let result = env.call_static_method(cls.as_ref(), &jni_fn_name, args.sig, &args.args);
    check_exceptions_and_convert_result(env, fn_name, result)
}

/// Calls a static method provided as a [`JStaticMethodID`].
///
/// Wraps [`jni::Env::call_static_method_unchecked`]. All the arguments are the same.
pub unsafe fn call_static_method_unchecked<'local, 'other_local, T, U>(
    env: &mut jni::Env<'local>,
    class: T,
    method_id: U,
    ret: jni::signature::ReturnType,
    args: &[jni::sys::jvalue],
) -> jni::errors::Result<JValueOwned<'local>>
where
    T: jni::descriptors::Desc<'local, JClass<'other_local>>,
    U: jni::descriptors::Desc<'local, JStaticMethodID>,
{
    let cls = class.lookup(env)?;
    let method_id = method_id.lookup(env)?;
    if cfg!(feature = "jni-invoke-annotated") {
        check_annotations::static_method_id(env, cls.as_ref(), *method_id.as_ref())?;
    }

    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    #[allow(clippy::disallowed_methods)]
    unsafe {
        env.call_static_method_unchecked(cls.as_ref(), method_id.as_ref(), ret, args)
    }
}

/// Constructs a new object using [`JniArgs`].
///
/// Wraps [`jni::Env::new_object`]; all arguments are the same.
pub fn new_object<'output, 'a, const LEN: usize>(
    env: &mut jni::Env<'output>,
    cls: impl AsRef<JClass<'a>>,
    args: JniArgs<(), LEN>,
) -> jni::errors::Result<JObject<'output>> {
    if cfg!(feature = "jni-invoke-annotated") {
        check_annotations::new_object(env, cls.as_ref(), &args.sig)?
    }
    #[allow(clippy::disallowed_methods)]
    env.new_object(cls.as_ref(), args.sig, &args.args)
}

/// Constructs a new object from a constructor [`JMethodID`].
///
/// Wraps [`jni::Env::new_object_unchecked`]; all arguments are the same.
pub unsafe fn new_object_unchecked<'local, 'other_local, T>(
    env: &mut jni::Env<'local>,
    class: T,
    ctor_id: JMethodID,
    ctor_args: &[jni::sys::jvalue],
) -> jni::errors::Result<JObject<'local>>
where
    T: jni::descriptors::Desc<'local, JClass<'other_local>>,
{
    let cls = class.lookup(env)?;
    if cfg!(feature = "jni-invoke-annotated") {
        check_annotations::new_object_id(env, cls.as_ref(), ctor_id)?;
    }

    #[allow(clippy::disallowed_methods)]
    unsafe {
        env.new_object_unchecked(cls.as_ref(), ctor_id, ctor_args)
    }
}

fn check_exceptions_and_convert_result<'output, R: TryFrom<JValueOwned<'output>>>(
    env: &mut jni::Env<'output>,
    fn_name: &'static str,
    result: jni::errors::Result<JValueOwned<'output>>,
) -> Result<R, BridgeLayerError> {
    let result = result.check_exceptions(env, fn_name)?;
    let type_name = result.type_name();
    result
        .try_into()
        .map_err(|_| BridgeLayerError::UnexpectedJniResultType(fn_name, type_name))
}

mod check_annotations {
    use jni::errors::Result;
    use jni::jni_str;
    use jni::objects::{Auto, JClass, JMethodID, JObject, JStaticMethodID};
    use jni::signature::MethodSignature;
    use jni::strings::JNIStr;

    use crate::jni::{ClassName, JniArgs};

    /// Check that the called constructor is annotated with `@CalledFromNative`.
    pub(super) fn new_object(
        env: &mut jni::Env<'_>,
        class: &JClass<'_>,
        signature: &MethodSignature,
    ) -> Result<()> {
        let ctor_id = env.get_method_id(class, jni_str!("<init>"), signature)?;
        new_object_id(env, class, ctor_id)
    }

    /// Check that the called constructor is annotated with `@CalledFromNative`.
    pub(super) fn new_object_id(
        env: &mut jni::Env<'_>,
        class: &JClass<'_>,
        ctor_id: JMethodID,
    ) -> Result<()> {
        let method = env.to_reflected_method(class, ctor_id)?;
        let method = Auto::new(method);

        call_enforcement_method(
            env,
            jni_str!("checkConstructor"),
            jni_args!((method => java.lang.reflect.Constructor) -> void),
        )
    }

    /// Check that the called method is annotated with `@CalledFromNative`.
    pub(super) fn called_method(
        env: &mut jni::Env<'_>,
        obj: &JObject<'_>,
        name: &JNIStr,
        signature: &MethodSignature,
    ) -> Result<()> {
        let method = {
            let cls = env.get_object_class(obj)?;
            let method = env.get_method_id(&cls, name, signature)?;

            env.to_reflected_method(&cls, method)?
        };
        let method = Auto::new(method);

        call_enforcement_method(
            env,
            jni_str!("checkCalledMethod"),
            jni_args!((method => java.lang.reflect.Method) -> void),
        )
    }

    /// Check that the called method is annotated with `@CalledFromNative`.
    pub(super) fn static_method(
        env: &mut jni::Env<'_>,
        cls: &JClass<'_>,
        name: &JNIStr,
        signature: &MethodSignature,
    ) -> Result<()> {
        let method_id = env.get_static_method_id(cls, name, signature)?;
        static_method_id(env, cls, method_id)
    }

    /// Check that the called method is annotated with `@CalledFromNative`.
    pub(super) fn static_method_id(
        env: &mut jni::Env<'_>,
        cls: &JClass<'_>,
        method_id: JStaticMethodID,
    ) -> Result<()> {
        let method = env.to_reflected_static_method(cls, method_id)?;
        let method = Auto::new(method);

        call_enforcement_method(
            env,
            jni_str!("checkCalledStaticMethod"),
            jni_args!((method => java.lang.reflect.Method) -> void),
        )
    }

    fn call_enforcement_method(
        env: &mut jni::Env<'_>,
        enforcement_name: &'static JNIStr,
        enforcement_args: JniArgs<(), 1>,
    ) -> Result<()> {
        // The rules are complicated to check and doing that via JNI just makes that
        // more difficult. Performance isn't critial here so defer to a helper
        // instead.
        let target = Auto::new(crate::jni::find_class(
            env,
            ClassName("org.signal.libsignal.internal.CalledFromNative$Enforcement"),
        )?);
        #[allow(clippy::disallowed_methods)]
        env.call_static_method(
            target,
            enforcement_name,
            enforcement_args.sig,
            &enforcement_args.args,
        )?
        .v()
    }
}
