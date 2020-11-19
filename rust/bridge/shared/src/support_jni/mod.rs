//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::sys::jlong;

pub(crate) use jni::objects::JClass;
pub(crate) use jni::JNIEnv;
pub(crate) use paste::paste;

pub type ObjectHandle = jlong;

macro_rules! bridge_destroy {
    ( $typ:ty $(, ffi = $ffi_name:ident)?, jni = $jni_name:ident ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<Java_org_signal_client_internal_Native_ $jni_name _1Destroy>](
                _env: JNIEnv,
                _class: JClass,
                handle: ObjectHandle,
            ) {
                if handle != 0 {
                    let _boxed_value = Box::from_raw(handle as *mut $typ);
                }
            }
        }
    };
    ( $typ:ty $(, ffi = $ffi_name:ident)? ) => {
        paste! {
            bridge_destroy!($typ, jni = $typ);
        }
    }
}
