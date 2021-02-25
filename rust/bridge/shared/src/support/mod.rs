//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures::pin_mut;
use futures::task::noop_waker_ref;
use std::borrow::Cow;
use std::future::Future;
use std::task::{self, Poll};

pub(crate) use paste::paste;

mod transform_helper;
pub(crate) use transform_helper::*;

/// Polls a future once; panics if it is not Ready.
#[allow(dead_code)] // not used in Node-only builds
#[track_caller]
pub fn expect_ready<F: Future>(future: F) -> F::Output {
    pin_mut!(future);
    match future.poll(&mut task::Context::from_waker(noop_waker_ref())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("future was not ready"),
    }
}

/// Used for returning newly-allocated buffers as efficiently as possible.
///
/// Functions marked `#[bridge_fn_buffer]` must have an `Env` as their first parameter.
pub(crate) trait Env {
    type Buffer;
    fn buffer<'a, T: Into<Cow<'a, [u8]>>>(self, input: T) -> Self::Buffer;
}

/// Wraps an expression in a function with a given name and type...
/// except that if the expression is a closure with a single typeless argument,
/// it's flattened into the function.
///
/// This allows the expression to return a value with a lifetime depending on the input.
macro_rules! expr_as_fn {
    ($name:ident $(<$l:lifetime>)? ($_:ident: $arg_ty:ty) -> $result:ty => |$arg:ident| $e:expr) => {
        fn $name $(<$l>)? ($arg: $arg_ty) -> $result { $e }
    };
    ($name:ident $(<$l:lifetime>)? ($arg:ident: $arg_ty:ty) -> $result:ty => $e:expr) => {
        fn $name $(<$l>)? ($arg: $arg_ty) -> $result { $e($arg) }
    };
}

/// Exposes a Rust type to each of the bridges as a boxed value.
///
/// Full form:
///
/// ```no_run
/// # #[macro_use] extern crate libsignal_bridge;
/// # struct Foo;
/// bridge_handle!(Foo, clone = true, mut = true, ffi = "foo", jni = "Foo", node = "Foo");
/// ```
///
/// This has several effects for a type `Foo`:
///
/// - `Foo` and `Option<Foo>` become valid result types for `bridge_fn`s (conforming to the
///   `ResultTypeInfo` traits for all three bridges).
///
/// - `&Foo` and `Option<&Foo>` become valid argument types (conforming to the `ArgTypeInfo` traits
///   for all three bridges).
///
/// - If `mut = true` is passed to `bridge_handle`, `&mut Foo` becomes a valid argument type for all
///   three bridges as well. This may include extra overhead to check Rust's exclusive borrow rules,
///   even for immutable accesses.
///
/// - If `mut = true` is *not* passed to `bridge_handle`, `&Foo` and `Option<&Foo>` become valid
///   argument types for async functions as well (conforming to [`node::AsyncArgTypeInfo`]).
///   (Note that you can't write `mut = false` because I was lazy with the macros.)
///
/// - "Destroy" functions are generated for FFI and JNI based on the name of the type:
///   `signal_foo_destroy` and `Native.Foo_Destroy`.
///
/// - If `clone = true` is passed to `bridge_handle`, a `signal_foo_clone` function will be
///   generated for the FFI bridge as well. `Foo` must adopt `Clone`.
///
/// # Representation
///
/// Each bridge represents a boxed Rust value differently:
///
/// - FFI: boxed values are opaque structs with manual memory management (`SignalFoo *`).
///   Note that the pointer may not refer directly to a `Foo` on the Rust side; that's an
///   implementation detail. (For example, it could point to a type tag.)
///
/// - JNI: boxed values are bare `long` values with manual memory management. (The Java code on the
///   other side of the bridge is expected to wrap these in strong class types.)
///
/// - Node: boxed values use Neon's [`JsBox`][] type, but this is only used for return values.
///   Arguments are always in the form of a JavaScript object with a `_nativeHandle` property that
///   refers to the box. The type inside the box may not directy be a `Foo` on the Rust side;
///   that's an implementation detail.
///
///   For TypeScript's benefit, each boxed type gets its own unique `interface Foo`, and the
///   arguments are of the form `Wrapper<Foo>`.
///
/// [`JsBox`]: https://docs.rs/neon/0.7.1-napi/neon/types/struct.JsBox.html
macro_rules! bridge_handle {
    ($typ:ty $(, clone = $_clone:tt)? $(, mut = $_mut:tt)? $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? $(, node = $node_name:ident)?) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_handle!($typ $(as $ffi_name)? $(, clone = $_clone)?);
        #[cfg(feature = "jni")]
        jni_bridge_handle!($typ $(as $jni_name)?);
        #[cfg(feature = "node")]
        node_bridge_handle!($typ $(as $node_name)? $(, mut = $_mut)?);
    };
}

/// Exposes a deserialization method to the bridges.
///
/// Example:
///
/// ```no_run
/// # #[macro_use] extern crate libsignal_bridge_macros;
/// # struct Foo;
/// # impl Foo {
/// #     fn try_from(buf: &[u8]) -> Result<Self, ()> {
/// #         Err(())
/// #     }
/// # }
///
/// bridge_deserialize!(Foo::try_from); // generates Foo_Deserialize
/// ```
///
/// The underlying method is expected to take a single `&[u8]` parameter and return
/// `Result<Self, _>`.
///
/// The `ffi`, `jni`, and `node` parameters control the name of the **type**; the resulting function
/// will always be suffixed with `_Deserialize` or `_deserialize` as appropriate. Unlike
/// `bridge_fn`, these parameters are identifiers, not string literals, and there is no way to
/// disable a particular bridge.
macro_rules! bridge_deserialize {
    ($typ:ident::$fn:path $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? $(, node = $node_name:ident)? ) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_deserialize!($typ::$fn $(as $ffi_name)?);
        #[cfg(feature = "jni")]
        jni_bridge_deserialize!($typ::$fn $(as $jni_name)?);
        #[cfg(feature = "node")]
        node_bridge_deserialize!($typ::$fn $(as $node_name)?);
    }
}

/// Exposes a buffer-returning getter to the bridges.
///
/// Example:
///
/// ```no_run
/// # #[macro_use] extern crate libsignal_bridge_macros;
/// # struct Foo;
/// # impl Foo {
/// #     fn payload(&self) -> Result<Vec<u8>, ()> {
/// #         Err(())
/// #     }
/// # }
///
/// bridge_get_bytearray!(Serialize(Foo) => Foo::payload); // generates Foo_Serialize
/// ```
///
/// The underlying implementation is expected to return a [`Result`] of a type that adopts
/// `AsRef<[u8]>`. Note that the most common "body" is a method name, but it can also be a closure.
///
/// Like `bridge_fn`, the `ffi`, `jni`, and `node` parameters allow customizing the name of the
/// resulting entry points; they can also be `false` to disable a particular entry point.
///
/// _Note: This is not currently based on `bridge_fn_buffer`, but it probably should be._
macro_rules! bridge_get_bytearray {
    ($name:ident($typ:ty) $(, ffi = $ffi_name:tt)? $(, jni = $jni_name:tt)? $(, node = $node_name:tt)? => $body:expr ) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_get_bytearray!($name($typ) $(as $ffi_name)? => $body);
        #[cfg(feature = "jni")]
        jni_bridge_get_bytearray!($name($typ) $(as $jni_name)? => $body);
        #[cfg(feature = "node")]
        node_bridge_get_bytearray!($name($typ) $(as $node_name)? => $body);
    }
}

/// Exposes an optional-buffer-returning getter to the bridges.
///
/// Example:
///
/// ```no_run
/// # #[macro_use] extern crate libsignal_bridge_macros;
/// # struct Foo;
/// # impl Foo {
/// #     fn payload(&self) -> Result<Option<Vec<u8>>, ()> {
/// #         Err(())
/// #     }
/// # }
///
/// bridge_get_optional_bytearray!(Payload(Foo) => Foo::payload); // generates Foo_Payload
/// ```
///
/// The underlying implementation is expected to return `Result<Option<T>, _>`, where `T` is a type
/// that adopts `AsRef<[u8]>`. Note that the most common "body" is a method name, but it can also
/// be a  closure.
///
/// Like `bridge_fn`, the `ffi`, `jni`, and `node` parameters allow customizing the name of the
/// resulting entry points; they can also be `false` to disable a particular entry point.
///
/// _Note: This is not currently based on `bridge_fn_buffer`, but it probably should be._
macro_rules! bridge_get_optional_bytearray {
    ($name:ident($typ:ty) $(, ffi = $ffi_name:tt)? $(, jni = $jni_name:tt)? $(, node = $node_name:tt)? => $body:expr ) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_get_optional_bytearray!($name($typ) $(as $ffi_name)? => $body);
        #[cfg(feature = "jni")]
        jni_bridge_get_optional_bytearray!($name($typ) $(as $jni_name)? => $body);
        #[cfg(feature = "node")]
        node_bridge_get_optional_bytearray!($name($typ) $(as $node_name)? => $body);
    }
}

/// Exposes a getter method as a `bridge_fn`.
///
/// Full form:
///
/// ```no_run
/// # #[macro_use] extern crate libsignal_bridge;
/// # struct Foo;
/// impl Foo {
///     fn bar(&self) -> &str {
///         // ...
/// #       "baz"
///     }
/// }
///
/// bridge_get!(Foo::bar as GetBar -> &str, ffi = "foo_get_bar", jni = "Foo_GetBar", node = "Foo_GetBar");
/// ```
///
/// The `as GetBar` can be omitted if the default name is acceptable (camel-case and prefix with
/// "Get"). All additional arguments are forwarded to `bridge_fn`.
///
/// Roughly equivalent to
///
/// ```no_run
/// # #[macro_use] extern crate libsignal_bridge_macros;
/// # struct Foo;
/// # impl Foo {
/// #     fn bar(&self) -> &str {
/// #         "baz"
/// #     }
/// # }
///
/// #[bridge_fn]
/// fn Foo_GetBar(obj: &Foo) -> Result<&str> {
///   Foo::bar(obj)   
/// }
/// ```
///
/// Automatically handles converting from the underlying type (using `into()`) and wrapping in
/// `Ok` if the underlying result is non-failable.
macro_rules! bridge_get {
    ($typ:ident :: $method:ident as $name:ident -> $result:ty $(, $param:ident = $val:tt)* ) => {
        paste! {
            #[bridge_fn($($param = $val),*)]
            fn [<$typ _ $name>](obj: &$typ) -> Result<$result> {
                let result = TransformHelper($typ::$method(obj));
                Ok(result.ok_if_needed()?.option_map_into().into())
            }
        }
    };
    ($typ:ident :: $method:ident -> $result:ty $(, $param:ident = $val:tt)* ) => {
        paste! {
            bridge_get!($typ::$method as [<Get $method:camel>] -> $result $(, $param = $val)*);
        }
    };
}
