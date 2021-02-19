//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::objects::{JObject, JValue};
use jni::sys::jint;
use jni::JNIEnv;

use libsignal_bridge::jni::*;
use libsignal_protocol::SignalProtocolError;

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

pub fn get_object_with_serialization(
    env: &JNIEnv,
    store_obj: JObject,
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
