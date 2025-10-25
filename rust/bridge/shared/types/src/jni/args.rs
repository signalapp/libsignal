//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;

use jni::objects::{JObject, JValue};

/// Converts a function or type signature to a JNI signature string.
///
/// This macro uses Rust function syntax `(Foo, Bar) -> Baz`, and uses Rust syntax for Java arrays
/// `[Foo]`, but otherwise uses Java names for types: `boolean`, `byte`, `void`. Inner classes are
/// indicated with `::` rather than `.`.
#[macro_export]
macro_rules! jni_signature {
    ( boolean ) => ("Z");
    ( bool ) => (compile_error!("use Java type 'boolean'"));
    ( byte ) => ("B");
    ( char ) => ("C");
    ( short ) => ("S");
    ( int ) => ("I");
    ( long ) => ("J");
    ( float ) => ("F");
    ( double ) => ("D");
    ( void ) => ("V");

    // Escape hatch: provide a literal string.
    ( $x:literal ) => ($x);

    // Arrays
    ( [$($contents:tt)+] ) => {
        concat!("[", $crate::jni_signature!($($contents)+))
    };

    // Classes
    ( $arg_base:tt $(. $arg_rest:ident)+ $(:: $nested:ident)* ) => {
        concat!(
            "L",
            stringify!($arg_base),
            $("/", stringify!($arg_rest),)+
            $("$", stringify!($nested),)*
            ";"
        )
    };

    // Functions
    (
        (
            $( $arg_base:tt $(. $arg_rest:ident)* $(:: $arg_nested:ident)* ),* $(,)?
        ) -> $ret_base:tt $(. $ret_rest:ident)* $(:: $ret_nested:ident)*
    ) => {
        concat!(
            "(",
            $( $crate::jni_signature!($arg_base $(. $arg_rest)* $(:: $arg_nested)*), )*
            ")",
            $crate::jni_signature!($ret_base $(. $ret_rest)* $(:: $ret_nested)*)
        )
    };
}

#[test]
fn test_jni_signature() {
    // Literals
    {
        assert_eq!(jni_signature!("Lfoo/bar;"), "Lfoo/bar;");
    }

    // Classes
    assert_eq!(jni_signature!(foo.bar), "Lfoo/bar;");
    assert_eq!(jni_signature!(foo.bar.baz), "Lfoo/bar/baz;");
    assert_eq!(jni_signature!(foo.bar.baz::garply), "Lfoo/bar/baz$garply;");
    assert_eq!(
        jni_signature!(foo.bar.baz::garply::qux),
        "Lfoo/bar/baz$garply$qux;"
    );

    // Arrays
    assert_eq!(jni_signature!([byte]), "[B");
    assert_eq!(jni_signature!([[byte]]), "[[B");
    assert_eq!(jni_signature!([foo.bar]), "[Lfoo/bar;");
    assert_eq!(
        jni_signature!([foo.bar.baz::garply::qux]),
        "[Lfoo/bar/baz$garply$qux;"
    );

    // Functions
    assert_eq!(jni_signature!(() -> void), "()V");
    assert_eq!(jni_signature!((byte, int) -> float), "(BI)F");
    assert_eq!(
        jni_signature!(([byte], foo.bar, foo.bar.baz::garply::qux) -> [byte]),
        "([BLfoo/bar;Lfoo/bar/baz$garply$qux;)[B"
    );
    assert_eq!(jni_signature!(() -> foo.bar), "()Lfoo/bar;");
    assert_eq!(
        jni_signature!(() -> foo.bar.baz::garply::qux),
        "()Lfoo/bar/baz$garply$qux;"
    );
}

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
    assert!(matches!(jni_arg!(true => boolean), JValue::Bool(1)));
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
    // Unfortunately there's not a conversion directly from JValue to bool, only jboolean.
    (boolean) => {
        u8
    };
    // jni_signature will reject this, but having it do something reasonable avoids multiple errors.
    (bool) => {
        u8
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
/// `JniArgs` covariant, which allows the compiler to be less strict about the lifetime marker.
pub type PhantomReturnType<R> = PhantomData<fn() -> R>;

/// A JNI argument list, type-checked with its signature.
#[derive(Debug, Clone, Copy)]
pub struct JniArgs<'local, 'obj_ref, R, const LEN: usize> {
    pub sig: &'static str,
    pub args: [JValue<'local, 'obj_ref>; LEN],
    pub _return: PhantomReturnType<R>,
}

impl<'local, 'obj_ref, 'output, const LEN: usize> JniArgs<'local, 'obj_ref, JObject<'output>, LEN> {
    /// Updates the lifetime of the return type.
    ///
    /// May be necessary when passing JniArgs into a "local frame"
    /// ([`jni::JNIEnv::with_local_frame`]).
    pub fn for_nested_frame<'new_output: 'output>(
        self,
    ) -> JniArgs<'local, 'obj_ref, JObject<'new_output>, LEN> {
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
/// assert_eq!(args.sig, "(Ljava/lang/String;S)V");
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
            sig: $crate::jni_signature!(
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
