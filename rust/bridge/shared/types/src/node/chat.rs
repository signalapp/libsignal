//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::panic::UnwindSafe;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use libsignal_net::chat::server_requests::DisconnectCause;
use libsignal_net::chat::{ChatConnection, ConnectError};
use libsignal_net_chat::api::Unauth;
use libsignal_protocol::Timestamp;
use neon::context::FunctionContext;
use neon::event::Channel;
use neon::handle::{Handle, Root};
use neon::prelude::{Context, Finalize, JsObject, Object};
use neon::result::NeonResult;
use signal_neon_futures::call_method;

use crate::net::ConnectionManager;
use crate::net::chat::{ChatListener, ServerMessageAck};
use crate::node::{PersistentBorrowedJsBoxedBridgeHandle, ResultTypeInfo, SignalNodeError as _};

#[derive(Clone)]
pub struct NodeChatListener {
    js_channel: Channel,
    roots: Arc<Roots>,
}

struct Roots {
    callback_object: Root<JsObject>,
}

impl ChatListener for NodeChatListener {
    fn received_incoming_message(
        &mut self,
        envelope: Bytes,
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

    fn received_alerts(&mut self, alerts: Vec<String>) {
        let roots_shared = self.roots.clone();
        self.js_channel.send(move |mut cx| {
            let callback_object_shared = &roots_shared.callback_object;
            let callback = callback_object_shared.to_inner(&mut cx);
            let js_alerts = cx.empty_array();
            // We use zip instead of enumerate here so that i is a u32 rather than usize.
            for (alert, i) in alerts.into_iter().zip(0..) {
                let js_alert = cx
                    .try_string(alert)
                    .unwrap_or_else(|_| cx.string("[invalid alert]"));
                js_alerts.set(&mut cx, i, js_alert)?;
            }
            let _result = call_method(&mut cx, callback, "_received_alerts", [js_alerts.upcast()])?;
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
            let Roots { callback_object } = &*roots_shared;
            let cause = disconnect_cause
                .map(|cause| cause.into_throwable(&mut cx, "connection_interrupted"))
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

        Ok(Self {
            js_channel: channel,
            roots: Arc::new(Roots {
                callback_object: callbacks.root(cx),
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
    }
}

pub struct NodeConnectChatFactory {
    // Option so that it can be moved on `Drop::drop`.
    connection_manager: Option<PersistentBorrowedJsBoxedBridgeHandle<ConnectionManager>>,
    // Only used in the `Drop` impl to provide a JS context for finalization.
    js_channel: Channel,
}

#[derive(Debug)]
pub struct NodeConnectChat {
    tokio_runtime: tokio::runtime::Handle,
    factory: NodeConnectChatFactory,
}

impl Debug for NodeConnectChatFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConnectChatFactory")
            .field("connection_manager", &"_")
            .field("js_channel", &self.js_channel)
            .finish()
    }
}

impl NodeConnectChatFactory {
    pub fn from_connection_manager_wrapper(
        cx: &mut FunctionContext,
        connection_manager_wrapper: Handle<JsObject>,
    ) -> NeonResult<Self> {
        let mut channel = cx.channel();
        channel.unref(cx);

        Ok(Self {
            js_channel: channel,
            connection_manager: Some(PersistentBorrowedJsBoxedBridgeHandle::new(
                cx,
                connection_manager_wrapper,
            )?),
        })
    }
}

impl crate::net::registration::ConnectChatBridge for NodeConnectChatFactory {
    fn create_chat_connector(
        self: Box<Self>,
        runtime: tokio::runtime::Handle,
    ) -> Box<dyn libsignal_net_chat::registration::ConnectUnauthChat + Send + Sync + UnwindSafe>
    {
        Box::new(NodeConnectChat {
            tokio_runtime: runtime,
            factory: *self,
        })
    }
}

impl Finalize for NodeConnectChatFactory {
    fn finalize<'a, C: Context<'a>>(mut self, cx: &mut C) {
        let Self {
            connection_manager,
            js_channel: _,
        } = &mut self;
        if let Some(connection_manager) = connection_manager.take() {
            connection_manager.finalize(cx);
        }
    }
}

impl Drop for NodeConnectChatFactory {
    fn drop(&mut self) {
        let Self {
            connection_manager,
            js_channel,
        } = self;
        if let Some(connection_manager) = connection_manager.take() {
            let _ = js_channel.send(move |mut cx| {
                connection_manager.finalize(&mut cx);
                Ok(())
            });
        }
    }
}

impl libsignal_net_chat::registration::ConnectUnauthChat for NodeConnectChat {
    fn connect_chat(
        &self,
        on_disconnect: tokio::sync::oneshot::Sender<std::convert::Infallible>,
    ) -> BoxFuture<'_, Result<Unauth<ChatConnection>, ConnectError>> {
        let Self {
            factory:
                NodeConnectChatFactory {
                    connection_manager,
                    js_channel: _,
                },
            tokio_runtime,
        } = self;
        let connection_manager = connection_manager.as_deref().expect("always Some");
        async move {
            crate::net::chat::connect_registration_chat(
                tokio_runtime,
                connection_manager,
                on_disconnect,
            )
            .await
        }
        .boxed()
    }
}
