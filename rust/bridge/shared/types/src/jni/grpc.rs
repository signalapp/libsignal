//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::*;
use std::cell::RefCell;

use async_trait::async_trait;

pub type JavaGrpcReplyListener<'a> = JObject<'a>;

pub struct JniGrpcReplyListener<'a> {
    env: RefCell<EnvHandle<'a>>,
    listener: &'a JObject<'a>,
}

impl<'a> JniGrpcReplyListener<'a> {
    pub fn new<'context: 'a>(env: &mut JNIEnv<'context>, listener: &'a JObject<'a>) -> Result<Self, BridgeLayerError> {
        check_jobject_type(
            env,
            &listener,
            ClassName("org.signal.libsignal.grpc.GrpcReplyListener"),
        )?;
        Ok(Self { env: EnvHandle::new(env).into(), listener })
    }
}

impl<'a> JniGrpcReplyListener<'a> {
    fn do_on_reply(&mut self, reply: GrpcReply) -> Result<(), BridgeLayerError> {
        self.env.borrow_mut().with_local_frame(8, |env| {
            let jni_reply = reply.convert_into(env)?;
            let callback_args = jni_args!((
                jni_reply => org.signal.libsignal.grpc.SignalRpcReply,
            ) -> void);
            call_method_checked(env, self.listener, "onReply", callback_args)?;

            Ok(())
        })
    }

    fn do_on_error(&mut self, error: String) -> Result<(), BridgeLayerError> {
        self.env.borrow_mut().with_local_frame(8, |env| {
            let message = env.new_string(error.to_string())?;
            let callback_args = jni_args!((
                message => java.lang.String,
            ) -> void);
            call_method_checked(env, self.listener, "onError", callback_args)?;

            Ok(())
        })
    }
}

#[async_trait(?Send)]
impl<'a> GrpcReplyListener for JniGrpcReplyListener<'a> {
    async fn on_reply(&mut self, reply: GrpcReply) -> Result<(), GrpcError> {
        self.do_on_reply(reply)
            .map_err(|e| GrpcError::InvalidArgument(format!("{}", e)))
    }

    async fn on_error(&mut self, error: String) -> Result<(), GrpcError> {
        self.do_on_error(error)
            .map_err(|e| GrpcError::InvalidArgument(format!("{}", e)))
    }
}
