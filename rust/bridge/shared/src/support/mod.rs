//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub(crate) use paste::paste;

mod serialized;
pub(crate) use serialized::*;

mod transform_helper;
pub(crate) use transform_helper::*;

// See https://github.com/rust-lang/rfcs/issues/1389
pub fn describe_panic(any: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(msg) = any.downcast_ref::<&str>() {
        msg.to_string()
    } else if let Some(msg) = any.downcast_ref::<String>() {
        msg.to_string()
    } else {
        "(break on rust_panic to debug)".to_string()
    }
}

/// Exposes a Rust type to each of the bridges as a boxed value.
///
/// Full form:
///
/// ```ignore
/// # #[macro_use] extern crate libsignal_bridge;
/// # struct Foo;
/// # #[cfg(ignore_even_when_running_all_tests)]
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
///   refers to the box. The type inside the box may not directly be a `Foo` on the Rust side;
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

/// Convenience syntax to expose a deserialization method to the bridges.
///
/// Example:
///
/// ```ignore
/// # #[macro_use] extern crate libsignal_bridge_macros;
/// # struct Foo;
/// # impl Foo {
/// #     fn try_from(buf: &[u8]) -> Result<Self, ()> {
/// #         Err(())
/// #     }
/// # }
/// #
/// # #[cfg(ignore_even_when_running_all_tests)]
/// bridge_deserialize!(Foo::try_from); // generates Foo_Deserialize
/// ```
///
/// The underlying method is expected to take a single `&[u8]` parameter and return
/// `Result<Self, _>`.
///
/// This function does not allow customizing which bridges are enabled, or the name of the bridge
/// functions that are generated (they are always suffixed with `_Deserialize` or `_deserialize`
/// as appropriate). If you need additional flexibility, use `bridge_fn` directly.
macro_rules! bridge_deserialize {
    ($typ:ident::$fn:path $(, $param:ident = $val:tt)*) => {
        paste! {
            #[bridge_fn($($param = $val),*)]
            fn [<$typ _Deserialize>](data: &[u8]) -> Result<$typ> {
                $typ::$fn(data)
            }
        }
    };
}

/// Exposes a getter method as a `bridge_fn`.
///
/// Full form:
///
/// ```ignore
/// # #[macro_use] extern crate libsignal_bridge;
/// # struct Foo;
/// impl Foo {
///     fn bar(&self) -> &str {
///         // ...
/// #       "baz"
///     }
/// }
///
/// # #[cfg(ignore_even_when_running_all_tests)]
/// bridge_get!(Foo::bar as GetBar -> &str, ffi = "foo_get_bar", jni = "Foo_GetBar", node = "Foo_GetBar");
/// ```
///
/// The `as GetBar` can be omitted if the default name is acceptable (camel-case and prefix with
/// "Get"). All additional arguments are forwarded to `bridge_fn`.
///
/// Roughly equivalent to
///
/// ```ignore
/// # #[macro_use] extern crate libsignal_bridge_macros;
/// # struct Foo;
/// # impl Foo {
/// #     fn bar(&self) -> &str {
/// #         "baz"
/// #     }
/// # }
///
/// # #[cfg(ignore_even_when_running_all_tests)]
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
