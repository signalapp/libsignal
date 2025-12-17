//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::panic::UnwindSafe;

use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use libsignal_net::chat::{ChatConnection, ConnectError};
use libsignal_net_chat::api::Unauth;
use neon::context::FunctionContext;
use neon::event::Channel;
use neon::handle::Handle;
use neon::prelude::{Context, Finalize, JsObject};
use neon::result::NeonResult;

use crate::net::ConnectionManager;
use crate::node::PersistentBorrowedJsBoxedBridgeHandle;

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
