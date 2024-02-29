//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::*;
use std::cell::RefCell;

use async_trait::async_trait;

pub type JavaQuicCallbackListener<'a> = JObject<'a>;

pub struct JniQuicCallbackListener<'a> {
    env: RefCell<EnvHandle<'a>>,
    listener: &'a JObject<'a>,
}

impl<'a> JniQuicCallbackListener<'a> {
    pub fn new<'context: 'a>(env: &mut JNIEnv<'context>, listener: &'a JObject<'a>) -> Result<Self, BridgeLayerError> {
        check_jobject_type(
            env,
            listener,
            jni_class_name!(org.signal.libsignal.quic.QuicCallbackListener),
        )?;
        Ok(Self { env: EnvHandle::new(env).into(), listener })
    }
}

impl<'a> JniQuicCallbackListener<'a> {
    fn do_on_data(&mut self, data: Vec<u8>) -> Result<(), BridgeLayerError> {
        self.env.borrow_mut().with_local_frame(8, |env| {
            let bytes = env.byte_array_from_slice(&data)?;
            let callback_args = jni_args!((
                bytes => [byte],
            ) -> void);
            call_method_checked(env, self.listener, "onData", callback_args)?;
    
            Ok(())
        })
    }
}

#[async_trait(?Send)]
impl<'a> QuicCallbackListener for JniQuicCallbackListener<'a> {
    async fn on_data(&mut self, data: Vec<u8>) -> Result<(), QuicError> {
        self.do_on_data(data)
            .map_err(|e| QuicError::InvalidArgument(format!("{}", e)))
    }
}
