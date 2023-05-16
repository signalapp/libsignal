//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::*;
use async_trait::async_trait;

pub type JavaGrpcReplyListener<'a> = JObject<'a>;

pub struct JniGrpcReplyListener<'a> {
    env: &'a JNIEnv<'a>,
    listener: JObject<'a>,
}

impl<'a> JniGrpcReplyListener<'a> {
    pub fn new(env: &'a JNIEnv, listener: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            env,
            listener,
            jni_class_name!(org.signal.libsignal.grpc.GrpcReplyListener),
        )?;
        Ok(Self { env, listener })
    }
}

impl<'a> JniGrpcReplyListener<'a> {
    fn do_on_reply(
        &mut self,
        reply: GrpcReply,
    ) -> Result<(), SignalJniError> {
        let callback_args = jni_args!((
            reply.convert_into(self.env)? => org.signal.libsignal.grpc.SignalRpcReply,
        ) -> void);
        call_method_checked(self.env, self.listener, "onReply", callback_args)?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a> GrpcReplyListener for JniGrpcReplyListener<'a> {
    async fn on_reply(
        &mut self,
        reply: GrpcReply,
    ) -> Result<(), GrpcError> {
        self.do_on_reply(reply).map_err(|e| GrpcError::InvalidArgument(format!("{}", e)))
    }
}
