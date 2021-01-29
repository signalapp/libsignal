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

macro_rules! bridge_handle {
    ($typ:ty) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_handle!($typ);
        #[cfg(feature = "jni")]
        jni_bridge_handle!($typ);
        #[cfg(feature = "node")]
        node_bridge_handle!($typ);
    };
}

macro_rules! bridge_destroy {
    ($typ:ty $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? $(, node = $node_name:ident)?) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_destroy!($typ $(as $ffi_name)?);
        #[cfg(feature = "jni")]
        jni_bridge_destroy!($typ $(as $jni_name)?);
        // The Node bridge doesn't need manual destruction.
    }
}

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

macro_rules! bridge_get_string {
    ($name:ident($typ:ty) $(, $param:ident = $val:tt)* => $body:expr ) => {
        paste! {
            #[bridge_fn($($param = $val),*)]
            fn [<$typ _ $name>](obj: &$typ) -> Result<String, SignalProtocolError> {
                expr_as_fn!(inner_get<'a>(
                    obj: &'a $typ
                ) -> Result<impl Into<String> + 'a, SignalProtocolError> => $body);
                Ok(inner_get(obj)?.into())
            }
        }
    }
}

macro_rules! bridge_get_optional_string {
    ($name:ident($typ:ty) $(, $param:ident = $val:tt)* => $body:expr ) => {
        paste! {
            #[bridge_fn($($param = $val),*)]
            fn [<$typ _ $name>](obj: &$typ) -> Result<Option<String>, SignalProtocolError> {
                expr_as_fn!(inner_get<'a>(
                    obj: &'a $typ
                ) -> Result<Option<impl Into<String> + 'a>, SignalProtocolError> => $body);
                Ok(inner_get(obj)?.map(|s| s.into()))
            }
        }
    }
}
