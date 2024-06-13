//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::net::chat::{ChatListener, MakeChatListener, ServerMessageAck};
use crate::node::ResultTypeInfo;
use libsignal_protocol::Timestamp;
use neon::context::FunctionContext;
use neon::event::Channel;
use neon::handle::{Handle, Root};
use neon::prelude::{Context, Finalize, JsObject, Object};
use signal_neon_futures::call_method;
use std::sync::Arc;

#[derive(Clone)]
pub struct NodeChatListener {
    js_channel: Channel,
    callback_object: Arc<Root<JsObject>>,
}

impl ChatListener for NodeChatListener {
    fn received_incoming_message(
        &mut self,
        envelope: Vec<u8>,
        timestamp: Timestamp,
        ack: ServerMessageAck,
    ) {
        let callback_object_shared = self.callback_object.clone();
        self.js_channel.send(move |mut cx| {
            let callback = callback_object_shared.to_inner(&mut cx);
            let ack = ack.convert_into(&mut cx)?;
            let timestamp = timestamp.convert_into(&mut cx)?.upcast();
            let envelope = envelope.convert_into(&mut cx)?.upcast();
            let _result = call_method(
                &mut cx,
                callback,
                "_incoming_message",
                [envelope, timestamp, ack],
            )?;
            callback_object_shared.finalize(&mut cx);
            Ok(())
        });
    }

    fn received_queue_empty(&mut self) {
        let callback_object_shared = self.callback_object.clone();
        self.js_channel.send(move |mut cx| {
            let callback = callback_object_shared.to_inner(&mut cx);
            let _result = call_method(&mut cx, callback, "_queue_empty", [])?;
            callback_object_shared.finalize(&mut cx);
            Ok(())
        });
    }
}

pub struct NodeMakeChatListener {
    listener: NodeChatListener,
}

impl NodeMakeChatListener {
    pub(crate) fn new(cx: &mut FunctionContext, callbacks: Handle<JsObject>) -> Self {
        let mut channel = cx.channel();
        channel.unref(cx);
        Self {
            listener: NodeChatListener {
                js_channel: channel,
                callback_object: Arc::new(callbacks.root(cx)),
            },
        }
    }
}

impl MakeChatListener for NodeMakeChatListener {
    fn make_listener(&self) -> Box<dyn ChatListener> {
        Box::new(self.listener.clone())
    }
}

impl Finalize for NodeMakeChatListener {
    fn finalize<'a, C: neon::prelude::Context<'a>>(self, cx: &mut C) {
        log::info!("finalize NodeMakeChatListener");
        self.listener.callback_object.finalize(cx);
        log::info!("finalize NodeMakeChatListener done");
    }
}
