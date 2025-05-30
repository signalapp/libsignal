//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::objects::{JClass, JMethodID, JObject, JStaticMethodID, JValueOwned};
use jni::JNIEnv;

use crate::jni::{BridgeLayerError, HandleJniError as _, JniArgs};

/// Calls a method and translates any thrown exceptions to
/// [`BridgeLayerError::CallbackException`].
///
/// Wraps [`JNIEnv::call_method`].
/// The result must have the correct type, or [`BridgeLayerError::UnexpectedJniResultType`] will be
/// returned instead.
pub fn call_method_checked<
    'input,
    'output,
    O: AsRef<JObject<'input>>,
    R: TryFrom<JValueOwned<'output>>,
    const LEN: usize,
>(
    env: &mut JNIEnv<'output>,
    obj: O,
    fn_name: &'static str,
    args: JniArgs<R, LEN>,
) -> Result<R, BridgeLayerError> {
    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    #[allow(clippy::disallowed_methods)]
    let result = env.call_method(obj, fn_name, args.sig, &args.args);
    check_exceptions_and_convert_result(env, fn_name, result)
}

/// Calls a method and translates any thrown exceptions to
/// [`BridgeLayerError::CallbackException`].
///
/// Wraps [`JNIEnv::call_static_method`].
/// The result must have the correct type, or [`BridgeLayerError::UnexpectedJniResultType`] will be
/// returned instead.
pub fn call_static_method_checked<
    'input,
    'output,
    C: jni::descriptors::Desc<'output, JClass<'input>>,
    R: TryFrom<JValueOwned<'output>>,
    const LEN: usize,
>(
    env: &mut JNIEnv<'output>,
    cls: C,
    fn_name: &'static str,
    args: JniArgs<R, LEN>,
) -> Result<R, BridgeLayerError> {
    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    #[allow(clippy::disallowed_methods)]
    let result = env.call_static_method(cls, fn_name, args.sig, &args.args);
    check_exceptions_and_convert_result(env, fn_name, result)
}

/// Calls a static method provided as a [`JStaticMethodID`].
///
/// Wraps [`JNIEnv::call_static_method_unchecked`]. All the arguments are the same.
pub unsafe fn call_static_method_unchecked<'local, 'other_local, T, U>(
    env: &mut JNIEnv<'local>,
    class: T,
    method_id: U,
    ret: jni::signature::ReturnType,
    args: &[jni::sys::jvalue],
) -> jni::errors::Result<JValueOwned<'local>>
where
    T: jni::descriptors::Desc<'local, JClass<'other_local>>,
    U: jni::descriptors::Desc<'local, JStaticMethodID>,
{
    #[allow(clippy::disallowed_methods)]
    env.call_static_method_unchecked(class, method_id, ret, args)
}

/// Constructs a new object using [`JniArgs`].
///
/// Wraps [`JNIEnv::new_object`]; all arguments are the same.
pub fn new_object<'output, 'a, const LEN: usize>(
    env: &mut JNIEnv<'output>,
    cls: impl jni::descriptors::Desc<'output, JClass<'a>>,
    args: JniArgs<(), LEN>,
) -> jni::errors::Result<JObject<'output>> {
    #[allow(clippy::disallowed_methods)]
    env.new_object(cls, args.sig, &args.args)
}

/// Constructs a new object from a constructor [`JMethodID`].
///
/// Wraps [`JNIEnv::new_object_unchecked`]; all arguments are the same.
pub unsafe fn new_object_unchecked<'local, 'other_local, T>(
    env: &mut JNIEnv<'local>,
    class: T,
    ctor_id: JMethodID,
    ctor_args: &[jni::sys::jvalue],
) -> jni::errors::Result<JObject<'local>>
where
    T: jni::descriptors::Desc<'local, JClass<'other_local>>,
{
    #[allow(clippy::disallowed_methods)]
    env.new_object_unchecked(class, ctor_id, ctor_args)
}

fn check_exceptions_and_convert_result<'output, R: TryFrom<JValueOwned<'output>>>(
    env: &mut JNIEnv<'output>,
    fn_name: &'static str,
    result: jni::errors::Result<JValueOwned<'output>>,
) -> Result<R, BridgeLayerError> {
    let result = result.check_exceptions(env, fn_name)?;
    let type_name = result.type_name();
    result
        .try_into()
        .map_err(|_| BridgeLayerError::UnexpectedJniResultType(fn_name, type_name))
}
