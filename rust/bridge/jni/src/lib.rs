//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]

use jni::objects::JClass;
use jni::sys::{jbyteArray, jlongArray, jobject};
use jni::JNIEnv;
use std::convert::TryFrom;

use libsignal_bridge::jni::*;
use libsignal_protocol::*;

pub mod logging;

type JavaCiphertextMessage = jobject;

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

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SessionCipher_1EncryptMessage(
    env: JNIEnv,
    _class: JClass,
    message: jbyteArray,
    protocol_address: ObjectHandle,
    session_store: JavaSessionStore,
    identity_key_store: JavaIdentityKeyStore,
) -> JavaCiphertextMessage {
    run_ffi_safe(&env, || {
        let message = env.convert_byte_array(message)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;

        let mut identity_key_store = JniIdentityKeyStore::new(&env, identity_key_store)?;
        let mut session_store = JniSessionStore::new(&env, session_store)?;

        let ctext = expect_ready(message_encrypt(
            &message,
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            None,
        ))?;

        let obj = match ctext {
            CiphertextMessage::SignalMessage(m) => jobject_from_native_handle(
                &env,
                "org/whispersystems/libsignal/protocol/SignalMessage",
                box_object::<SignalMessage>(Ok(m))?,
            ),
            CiphertextMessage::PreKeySignalMessage(m) => jobject_from_native_handle(
                &env,
                "org/whispersystems/libsignal/protocol/PreKeySignalMessage",
                box_object::<PreKeySignalMessage>(Ok(m))?,
            ),
            _ => Err(SignalJniError::Signal(SignalProtocolError::InternalError(
                "Unexpected result type from message_encrypt",
            ))),
        };

        Ok(obj?.into_inner())
    })
}
