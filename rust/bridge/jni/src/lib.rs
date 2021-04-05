//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]

use jni::objects::JClass;
use jni::sys::{jbyteArray, jlongArray};
use jni::JNIEnv;
use std::convert::TryFrom;

use libsignal_bridge::jni::*;
use libsignal_protocol::*;

pub mod logging;

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_IdentityKeyPair_1Deserialize(
    env: JNIEnv,
    _class: JClass,
    data: jbyteArray,
) -> jlongArray {
    run_ffi_safe(&env, || {
        let data = env.convert_byte_array(data)?;
        let key = IdentityKeyPair::try_from(data.as_ref())?;

        let public_key_handle = box_object(Ok(*key.identity_key().public_key()))?;
        let private_key_handle = box_object(Ok(*key.private_key()))?;
        let tuple = [public_key_handle, private_key_handle];

        let result = env.new_long_array(2)?;
        env.set_long_array_region(result, 0, &tuple)?;
        Ok(result)
    })
}
