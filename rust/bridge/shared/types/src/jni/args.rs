//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;

use jni::objects::{JObject, JValue};
use jni::signature::MethodSignature;

#[macro_export]
macro_rules! jni_arg {
    ( $arg:expr => boolean ) => {
        <$crate::jni::JValue as From<bool>>::from($arg)
    };
    // jni_signature will reject this, but having it do something reasonable avoids multiple errors.
    ( $arg:expr => bool ) => {
        <$crate::jni::JValue as From<bool>>::from($arg)
    };
    ( $arg:expr => byte ) => {
        $crate::jni::JValue::Byte($arg)
    };
    ( $arg:expr => char ) => {
        $crate::jni::JValue::Char($arg)
    };
    ( $arg:expr => short ) => {
        $crate::jni::JValue::Short($arg)
    };
    ( $arg:expr => int ) => {
        $crate::jni::JValue::Int($arg)
    };
    ( $arg:expr => long ) => {
        $crate::jni::JValue::Long($arg)
    };
    ( $arg:expr => float ) => {
        $crate::jni::JValue::Float($arg)
    };
    ( $arg:expr => double ) => {
        $crate::jni::JValue::Double($arg)
    };
    // Assume anything else is an object. This includes arrays and classes.
    ( $arg:expr => $($_:tt)+) => {
        $crate::jni::JValue::Object($arg.as_ref())
    };
}

#[test]
fn test_jni_arg() {
    assert!(matches!(jni_arg!(true => boolean), JValue::Bool(true)));
    assert!(matches!(jni_arg!(0x8000 => char), JValue::Char(0x8000)));
    assert!(matches!(jni_arg!(-80 => byte), JValue::Byte(-80)));
    assert!(matches!(jni_arg!(-80 => short), JValue::Short(-80)));
    assert!(matches!(jni_arg!(-80 => int), JValue::Int(-80)));
    assert!(matches!(jni_arg!(-80 => long), JValue::Long(-80)));
    assert!(matches!(jni_arg!(-8.5 => float), JValue::Float(val) if val == -8.5));
    assert!(matches!(jni_arg!(-8.5 => double), JValue::Double(val) if val == -8.5));
    assert!(matches!(
        jni_arg!(jni::objects::JObject::null() => java.lang.Object),
        JValue::Object(val) if val.is_null()
    ));
}

#[macro_export]
macro_rules! jni_return_type {
    (boolean) => {
        bool
    };
    // jni_signature will reject this, but having it do something reasonable avoids multiple errors.
    (bool) => {
        bool
    };
    (byte) => {
        i8,
    };
    (char) => {
        u16,
    };
    (short) => {
        i16
    };
    (int) => {
        i32
    };
    (long) => {
        i64
    };
    (float) => {
        f32
    };
    (double) => {
        f64
    };
    (void) => {
        ()
    };
    // Assume anything else is an object. This includes arrays and classes.
    ($($_:tt)+) => {
        JObject
    };
}

/// Represents a return type, used by [`JniArgs`].
///
/// This is an implementation detail of [`jni_args`] and [`JniArgs`]. Using a function type makes
/// `JniArgs` covariant, which allows the compiler to be less strict about the lifetime of the
/// result. Having a lifetime *input* allows the result to depend on the JNI environment, which is
/// important for callbacks.
pub type PhantomReturnType<'local, R> = PhantomData<fn(&'local ()) -> R>;

/// A JNI argument list, type-checked with its signature.
#[derive(Debug, Clone)]
pub struct JniArgs<'sig, 'input, 'output, R, const LEN: usize> {
    pub sig: MethodSignature<'sig, 'sig>,
    pub args: [JValue<'input>; LEN],
    pub _return: PhantomReturnType<'output, R>,
}

impl<'sig, 'input, 'output_env, 'output_obj, const LEN: usize>
    JniArgs<'sig, 'input, 'output_env, JObject<'output_obj>, LEN>
{
    /// Updates the lifetime of the return type.
    ///
    /// May be necessary when passing JniArgs into a "local frame"
    /// ([`jni::Env::with_local_frame`]).
    pub fn for_nested_frame<'new_output: 'output_obj>(
        self,
    ) -> JniArgs<'sig, 'input, 'new_output, JObject<'new_output>, LEN> {
        JniArgs {
            sig: self.sig,
            args: self.args,
            _return: PhantomData,
        }
    }
}

/// Produces a JniArgs struct from the given arguments and return type.
///
/// # Example
///
/// ```
/// # use libsignal_bridge_types::jni_args;
/// # use jni::objects::JValue;
/// # let name = jni::objects::JObject::null();
/// let args = jni_args!((name => java.lang.String, 0x3FFF => short) -> void);
/// assert_eq!(args.sig.sig().as_cstr(), c"(Ljava/lang/String;S)V");
/// assert_eq!(args.args.len(), 2);
/// ```
#[macro_export]
macro_rules! jni_args {
    (
        (
            $( $arg:expr => $arg_base:tt $(. $arg_rest:ident)* $(:: $arg_nested:ident)* ),* $(,)?
        ) -> $ret_base:tt $(. $ret_rest:ident)* $(:: $ret_nested:ident)*
    ) => {
        $crate::jni::JniArgs {
            sig: ::jni::jni_sig!(
                (
                    $( $arg_base $(. $arg_rest)* $(:: $arg_nested)* ),*
                ) -> $ret_base $(. $ret_rest)* $(:: $ret_nested)*
            ),
            args: [$($crate::jni_arg!($arg => $arg_base)),*],
            _return: $crate::jni::PhantomReturnType::<$crate::jni_return_type!($ret_base)> {},
        }
    }
}
// Expose this for doc comments.
#[cfg(doc)]
use jni_args;
