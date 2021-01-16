//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::objects::{JObject, JValue};
use jni::sys::{jint, jlong, jobject};
use jni::JNIEnv;

use libsignal_bridge::jni::*;
use libsignal_protocol_rust::SignalProtocolError;

pub unsafe fn native_handle_cast_optional<T>(
    handle: ObjectHandle,
) -> Result<Option<&'static mut T>, SignalJniError> {
    if handle == 0 {
        return Ok(None);
    }

    Ok(Some(&mut *(handle as *mut T)))
}

pub fn jint_from_u32(value: Result<u32, SignalProtocolError>) -> Result<jint, SignalJniError> {
    match value {
        Ok(value) => {
            let result = value as jint;
            if result as u32 != value {
                return Err(SignalJniError::IntegerOverflow(format!(
                    "{} to jint",
                    value
                )));
            }
            Ok(result)
        }
        Err(e) => Err(SignalJniError::Signal(e)),
    }
}

pub fn jlong_from_u64(value: Result<u64, SignalProtocolError>) -> Result<jlong, SignalJniError> {
    match value {
        Ok(value) => {
            let result = value as jlong;
            if result as u64 != value {
                return Err(SignalJniError::IntegerOverflow(format!(
                    "{} to jlong",
                    value
                )));
            }
            Ok(result)
        }
        Err(e) => Err(SignalJniError::Signal(e)),
    }
}

pub fn check_jobject_type(
    env: &JNIEnv,
    obj: jobject,
    class_name: &'static str,
) -> Result<(), SignalJniError> {
    if obj.is_null() {
        return Err(SignalJniError::NullHandle);
    }

    let class = env.find_class(class_name)?;

    if !env.is_instance_of(obj, class)? {
        return Err(SignalJniError::BadJniParameter(class_name));
    }

    Ok(())
}

pub fn get_object_with_native_handle<T: 'static + Clone>(
    env: &JNIEnv,
    store_obj: jobject,
    callback_args: &[JValue],
    callback_sig: &'static str,
    callback_fn: &'static str,
) -> Result<Option<T>, SignalJniError> {
    let rvalue = call_method_checked(env, store_obj, callback_fn, callback_sig, &callback_args)?;

    let obj = match rvalue {
        JValue::Object(o) => *o,
        _ => {
            return Err(SignalJniError::UnexpectedJniResultType(
                callback_fn,
                rvalue.type_name(),
            ))
        }
    };

    if obj.is_null() {
        return Ok(None);
    }

    let handle = call_method_checked(env, obj, "nativeHandle", "()J", &[])?;
    match handle {
        JValue::Long(handle) => {
            if handle == 0 {
                return Ok(None);
            }
            let object = unsafe { native_handle_cast::<T>(handle)? };
            Ok(Some(object.clone()))
        }
        _ => Err(SignalJniError::UnexpectedJniResultType(
            "nativeHandle",
            handle.type_name(),
        )),
    }
}

pub fn get_object_with_serialization(
    env: &JNIEnv,
    store_obj: jobject,
    callback_args: &[JValue],
    callback_sig: &'static str,
    callback_fn: &'static str,
) -> Result<Option<Vec<u8>>, SignalJniError> {
    let rvalue = call_method_checked(env, store_obj, callback_fn, callback_sig, &callback_args)?;

    let obj = match rvalue {
        JValue::Object(o) => *o,
        _ => {
            return Err(SignalJniError::UnexpectedJniResultType(
                callback_fn,
                rvalue.type_name(),
            ))
        }
    };

    if obj.is_null() {
        return Ok(None);
    }

    let bytes = call_method_checked(env, obj, "serialize", "()[B", &[])?;

    match bytes {
        JValue::Object(o) => Ok(Some(env.convert_byte_array(*o)?)),
        _ => Err(SignalJniError::UnexpectedJniResultType(
            "serialize",
            bytes.type_name(),
        )),
    }
}

pub fn jobject_from_serialized<'a>(
    env: &'a JNIEnv,
    class_name: &str,
    serialized: &[u8],
) -> Result<JObject<'a>, SignalJniError> {
    let class_type = env.find_class(class_name)?;
    let ctor_sig = "([B)V";
    let ctor_args = [JValue::from(to_jbytearray(env, Ok(serialized))?)];
    Ok(env.new_object(class_type, ctor_sig, &ctor_args)?)
}

pub fn jobject_from_native_handle<'a>(
    env: &'a JNIEnv,
    class_name: &str,
    boxed_handle: ObjectHandle,
) -> Result<JObject<'a>, SignalJniError> {
    let class_type = env.find_class(class_name)?;
    let ctor_sig = "(J)V";
    let ctor_args = [JValue::from(boxed_handle)];
    Ok(env.new_object(class_type, ctor_sig, &ctor_args)?)
}

#[macro_export]
macro_rules! jni_fn_get_new_boxed_obj {
    ( $nm:ident($rt:ty) from $typ:ty, $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            env: JNIEnv,
            _class: JClass,
            handle: ObjectHandle,
        ) -> ObjectHandle {
            run_ffi_safe(&env, || {
                let obj = native_handle_cast::<$typ>(handle)?;
                box_object::<$rt>($body(obj))
            })
        }
    };
}

#[macro_export]
macro_rules! jni_fn_get_new_boxed_optional_obj {
    ( $nm:ident($rt:ty) from $typ:ty, $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            env: JNIEnv,
            _class: JClass,
            handle: ObjectHandle,
        ) -> ObjectHandle {
            run_ffi_safe(&env, || {
                let obj = native_handle_cast::<$typ>(handle)?;
                let result: Option<$rt> = $body(obj)?;
                if let Some(result) = result {
                    box_object::<$rt>(Ok(result))
                } else {
                    Ok(0 as ObjectHandle)
                }
            })
        }
    };
}

#[macro_export]
macro_rules! jni_fn_get_jint {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(env: JNIEnv, _class: JClass, handle: ObjectHandle) -> jint {
            run_ffi_safe(&env, || {
                let obj = native_handle_cast::<$typ>(handle)?;
                jint_from_u32($body(obj))
            })
        }
    };
}

#[macro_export]
macro_rules! jni_fn_get_jlong {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(env: JNIEnv, _class: JClass, handle: ObjectHandle) -> jlong {
            run_ffi_safe(&env, || {
                let obj = native_handle_cast::<$typ>(handle)?;
                jlong_from_u64($body(obj))
            })
        }
    };
}

#[macro_export]
macro_rules! jni_fn_get_jboolean {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            env: JNIEnv,
            _class: JClass,
            handle: ObjectHandle,
        ) -> jboolean {
            run_ffi_safe(&env, || {
                let obj = native_handle_cast::<$typ>(handle)?;
                let r: bool = $body(obj)?;
                Ok(r as jboolean)
            })
        }
    };
}
