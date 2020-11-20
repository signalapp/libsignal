//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub use paste::paste;

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
