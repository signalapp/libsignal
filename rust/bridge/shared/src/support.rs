//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures::pin_mut;
use futures::task::noop_waker_ref;
use std::future::Future;
use std::task::{self, Poll};

pub(crate) use paste::paste;

#[track_caller]
pub fn expect_ready<F: Future>(future: F) -> F::Output {
    pin_mut!(future);
    match future.poll(&mut task::Context::from_waker(noop_waker_ref())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("future was not ready"),
    }
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

macro_rules! bridge_destroy {
    ($typ:ty $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? ) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_destroy!($typ $(as $ffi_name)?);
        #[cfg(feature = "jni")]
        jni_bridge_destroy!($typ $(as $jni_name)?);
    }
}

macro_rules! bridge_deserialize {
    ($typ:ident::$fn:path $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? ) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_deserialize!($typ::$fn $(as $ffi_name)?);
        #[cfg(feature = "jni")]
        jni_bridge_deserialize!($typ::$fn $(as $jni_name)?);
    }
}

macro_rules! bridge_get_bytearray {
    ($name:ident($typ:ty) $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? => $body:expr ) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_get_bytearray!($name($typ) $(as $ffi_name)? => $body);
        #[cfg(feature = "jni")]
        jni_bridge_get_bytearray!($name($typ) $(as $jni_name)? => $body);
    }
}

macro_rules! bridge_get_optional_bytearray {
    ($name:ident($typ:ty) $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? => $body:expr ) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_get_optional_bytearray!($name($typ) $(as $ffi_name)? => $body);
        #[cfg(feature = "jni")]
        jni_bridge_get_optional_bytearray!($name($typ) $(as $jni_name)? => $body);
    }
}

macro_rules! bridge_get_string {
    ($name:ident($typ:ty) $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? => $body:expr ) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_get_string!($name($typ) $(as $ffi_name)? => $body);
        #[cfg(feature = "jni")]
        jni_bridge_get_string!($name($typ) $(as $jni_name)? => $body);
    }
}

macro_rules! bridge_get_optional_string {
    ($name:ident($typ:ty) $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? => $body:expr ) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_get_optional_string!($name($typ) $(as $ffi_name)? => $body);
        #[cfg(feature = "jni")]
        jni_bridge_get_optional_string!($name($typ) $(as $jni_name)? => $body);
    }
}
