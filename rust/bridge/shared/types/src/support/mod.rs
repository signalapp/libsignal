//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::num::NonZeroU64;

mod as_type;
mod sequences;
mod serialized;
pub use as_type::*;
pub use sequences::*;
pub use serialized::*;

mod transform_helper;
pub use transform_helper::*;

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

/// Extremely unsafe function to extend the lifetime of a reference.
///
/// Only here so that we're not directly calling [`std::mem::transmute`], which is even more unsafe.
/// All call sites need to explain why extending the lifetime is safe.
#[cfg(any(feature = "ffi", feature = "node"))]
pub(crate) unsafe fn extend_lifetime<'a, 'b: 'a, T: ?Sized>(some_ref: &'a T) -> &'b T {
    std::mem::transmute::<&'a T, &'b T>(some_ref)
}

/// With `bridge_handle_fns`, exposes a Rust type to each of the bridges as a boxed value.
///
/// Full form:
///
/// ```ignore
/// # struct Foo;
/// # #[cfg(ignore_even_when_running_all_tests)]
/// bridge_as_handle!(Foo, mut = true, ffi = foo, jni = Foo, node = Foo);
/// # #[cfg(ignore_even_when_running_all_tests)]
/// bridge_handle_fns!(Foo, ffi = foo, jni = Foo, node = Foo);
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
/// - If `mut = true` is passed to `bridge_as_handle`, `&mut Foo` becomes a valid argument type for all
///   three bridges as well. This may include extra overhead to check Rust's exclusive borrow rules,
///   even for immutable accesses.
///
/// - If `mut = true` is *not* passed to `bridge_as_handle`, `&Foo` and `Option<&Foo>` become valid
///   argument types for async functions as well (conforming to [`node::AsyncArgTypeInfo`]).
///   (Note that you can't write `mut = false` because I was lazy with the macros.)
///
/// - "Destroy" functions are generated for FFI and JNI based on the name of the type:
///   `signal_foo_destroy` and `Native.Foo_Destroy`.
///
/// - If `clone = true` is passed to `bridge_handle_fns`, a `signal_foo_clone` function will be
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
/// [`node::AsyncArgTypeInfo`]: crate::node::AsyncArgTypeInfo
#[macro_export]
macro_rules! bridge_as_handle {
    ($typ:ty $(, mut = $_mut:tt)? $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? $(, node = $node_name:ident)?) => {
        #[cfg(feature = "ffi")]
        $crate::ffi_bridge_as_handle!($typ $(as $ffi_name)?);
        #[cfg(feature = "jni")]
        $crate::jni_bridge_as_handle!($typ $(as $jni_name)?);
        #[cfg(feature = "node")]
        $crate::node_bridge_as_handle!($typ $(as $node_name)? $(, mut = $_mut)?);
    };
}

/// See [`bridge_as_handle`].
#[macro_export]
macro_rules! bridge_handle_fns {
    ($typ:ty $(, clone = $_clone:tt)? $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? $(, node = $node_name:ident)?) => {
        #[cfg(feature = "ffi")]
        $crate::ffi_bridge_handle_fns!($typ $(as $ffi_name)? $(, clone = $_clone)?);
        #[cfg(feature = "jni")]
        $crate::jni_bridge_handle_fns!($typ $(as $jni_name)?);
        // Node doesn't need any generated bridging functions
    };
}

// Allow referring to the macro by path in doc comments.
#[cfg(doc)]
pub use {bridge_as_handle, bridge_handle_fns};

/// Convenience syntax to expose a deserialization method to the bridges.
///
/// Example:
///
/// ```ignore
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
#[macro_export]
macro_rules! bridge_deserialize {
    ($typ:ident::$fn:path $(, $param:ident = $val:tt)*) => {
        ::paste::paste! {
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
#[macro_export]
macro_rules! bridge_get {
    ($typ:ident :: $method:ident as $name:ident -> $result:ty $(, $param:ident = $val:tt)* ) => {
        ::paste::paste! {
            #[bridge_fn($($param = $val),*)]
            fn [<$typ _ $name>](obj: &$typ) -> Result<$result> {
                let result = TransformHelper($typ::$method(obj));
                Ok(result.ok_if_needed()?.option_map_into().into())
            }
        }
    };
    ($typ:ident :: $method:ident -> $result:ty $(, $param:ident = $val:tt)* ) => {
        ::paste::paste! {
            bridge_get!($typ::$method as [<Get $method:camel>] -> $result $(, $param = $val)*);
        }
    };
}

/// Reports a result from a future to some receiver.
pub trait ResultReporter {
    /// The type that will receive the result.
    type Receiver;

    /// Reports the result to the provided completer.
    fn report_to(self, receiver: Self::Receiver);
}

/// ID for a future run by an [`AsyncRuntime`].
///
/// `AsyncRuntime`s that support cancellation are recommended to use a simple autoincrementing
/// counter to generate IDs---2^64 *nanoseconds* is over 500 years.
///
/// This type is designed to not need cleanup across language bridges.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, derive_more::From)]
pub enum CancellationId {
    NotSupported,
    Id(NonZeroU64),
}

impl From<CancellationId> for u64 {
    fn from(value: CancellationId) -> Self {
        match value {
            CancellationId::NotSupported => 0,
            CancellationId::Id(value) => value.into(),
        }
    }
}

impl From<u64> for CancellationId {
    fn from(value: u64) -> Self {
        match NonZeroU64::try_from(value) {
            Ok(value) => Self::Id(value),
            Err(_) => Self::NotSupported,
        }
    }
}

/// Contains methods of [`AsyncRuntime`] that don't depend on the type of Futures being run.
pub trait AsyncRuntimeBase {
    /// Opportunistically, cooperatively cancels the future associated with the given token.
    ///
    /// This is different from the usual Rust paradigm of simply dropping a future for a few
    /// reasons:
    /// - Bridged tasks often have saved state they need to clean up (hence the Reporter interface).
    /// - We want the cancellation token itself to not need cleanup.
    /// - We may still need *some* output to be reported, depending on how the future's result is
    ///   being consumed.
    ///
    /// If a particular `AsyncRuntime` does not support cancellation, this method does nothing.
    fn cancel(&self, cancellation_token: CancellationId) {
        if cancellation_token != CancellationId::NotSupported {
            log::warn!("this runtime does not support cancellation ({cancellation_token:?})");
        }
    }
}

/// Abstracts over executing a future with type `F`.
///
/// Putting the future type in the trait signature allows runtimes to impose additional
/// requirements, such as `Send`, on the Futures they can run.
pub trait AsyncRuntime<F: Future<Output: ResultReporter>>: AsyncRuntimeBase {
    type Cancellation: Future<Output = ()>;

    /// Runs the provided future to completion, then reports the result.
    ///
    /// Executes the provided future to completion, then reports the output to
    /// the provided completer.
    fn run_future(
        &self,
        make_future: impl FnOnce(Self::Cancellation) -> F,
        completer: <F::Output as ResultReporter>::Receiver,
    ) -> CancellationId;
}

#[doc(hidden)]
/// An `AsyncRuntime` implementer that doesn't do anything.
///
/// This should only be used for writing doctests.
pub struct NoOpAsyncRuntime;

impl AsyncRuntimeBase for NoOpAsyncRuntime {}

impl<F: Future<Output: ResultReporter>> AsyncRuntime<F> for NoOpAsyncRuntime {
    type Cancellation = std::future::Pending<()>;

    fn run_future(
        &self,
        _make_future: impl FnOnce(Self::Cancellation) -> F,
        _completer: <F::Output as ResultReporter>::Receiver,
    ) -> CancellationId {
        CancellationId::NotSupported
    }
}
