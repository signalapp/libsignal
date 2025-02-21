//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;

use libsignal_net::chat::server_requests::DisconnectCause;
use libsignal_protocol::Timestamp;
use neon::context::FunctionContext;
use neon::event::Channel;
use neon::handle::{Handle, Root};
use neon::prelude::{Context, Finalize, JsObject, Object};
use neon::result::NeonResult;
use signal_neon_futures::call_method;

use crate::net::chat::{ChatListener, ServerMessageAck};
use crate::node::{ResultTypeInfo, SignalNodeError as _};

#[derive(Clone)]
pub struct NodeChatListener {
    js_channel: Channel,
    roots: Arc<Roots>,
}

struct Roots {
    callback_object: Root<JsObject>,
    module: Root<JsObject>,
}

impl ChatListener for NodeChatListener {
    fn received_incoming_message(
        &mut self,
        envelope: Vec<u8>,
        timestamp: Timestamp,
        ack: ServerMessageAck,
    ) {
        let roots_shared = self.roots.clone();
        self.js_channel.send(move |mut cx| {
            let callback_object_shared = &roots_shared.callback_object;
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
            roots_shared.finalize(&mut cx);
            Ok(())
        });
    }

    fn received_queue_empty(&mut self) {
        let roots_shared = self.roots.clone();
        self.js_channel.send(move |mut cx| {
            let callback_object_shared = &roots_shared.callback_object;
            let callback = callback_object_shared.to_inner(&mut cx);
            let _result = call_method(&mut cx, callback, "_queue_empty", [])?;
            roots_shared.finalize(&mut cx);
            Ok(())
        });
    }

    fn connection_interrupted(&mut self, disconnect_cause: DisconnectCause) {
        let disconnect_cause = match disconnect_cause {
            DisconnectCause::LocalDisconnect => None,
            DisconnectCause::Error(cause) => Some(cause),
        };
        let roots_shared = self.roots.clone();
        self.js_channel.send(move |mut cx| {
            let Roots {
                callback_object,
                module,
            } = &*roots_shared;
            let module = module.to_inner(&mut cx);
            let cause = disconnect_cause
                .map(|cause| cause.into_throwable(&mut cx, module, "connection_interrupted"))
                .convert_into(&mut cx)?;

            let callback = callback_object.to_inner(&mut cx);
            let _result = call_method(&mut cx, callback, "_connection_interrupted", [cause])?;
            roots_shared.finalize(&mut cx);
            Ok(())
        });
    }
}

impl NodeChatListener {
    pub(crate) fn new(cx: &mut FunctionContext, callbacks: Handle<JsObject>) -> NeonResult<Self> {
        let mut channel = cx.channel();
        channel.unref(cx);

        let module = cx.this::<JsObject>()?;

        Ok(Self {
            js_channel: channel,
            roots: Arc::new(Roots {
                callback_object: callbacks.root(cx),
                module: module.root(cx),
            }),
        })
    }

    pub(crate) fn make_listener(&self) -> Box<dyn ChatListener> {
        Box::new(self.clone())
    }
}

impl Finalize for NodeChatListener {
    fn finalize<'a, C: neon::prelude::Context<'a>>(self, cx: &mut C) {
        log::info!("finalize NodeChatListener");
        self.roots.finalize(cx);
        log::info!("finalize NodeChatListener done");
    }
}

impl Finalize for Roots {
    fn finalize<'a, C: neon::prelude::Context<'a>>(self, cx: &mut C) {
        self.callback_object.finalize(cx);
        self.module.finalize(cx);
    }
}
