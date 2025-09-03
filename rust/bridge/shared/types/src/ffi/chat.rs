//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ffi::{c_uchar, c_void};
use std::panic::UnwindSafe;

use bytes::Bytes;
use futures_util::FutureExt as _;
use futures_util::future::BoxFuture;
use libsignal_net::chat::server_requests::DisconnectCause;
use libsignal_net::chat::{ChatConnection, ConnectError};
use libsignal_net_chat::api::Unauth;
use libsignal_net_chat::registration::ConnectUnauthChat;

use super::*;
use crate::net::ConnectionManager;
use crate::net::chat::{ChatListener, ServerMessageAck};
use crate::net::registration::ConnectChatBridge;

type ReceivedIncomingMessage = extern "C" fn(
    ctx: *mut c_void,
    envelope: OwnedBufferOf<c_uchar>,
    timestamp_millis: u64,
    cleanup: *mut ServerMessageAck,
);
type ReceivedQueueEmpty = extern "C" fn(ctx: *mut c_void);
type ReceivedAlerts = extern "C" fn(ctx: *mut c_void, alerts: StringArray);
type ConnectionInterrupted = extern "C" fn(ctx: *mut c_void, error: *mut SignalFfiError);
type DestroyChatListener = extern "C" fn(ctx: *mut c_void);

/// Callbacks for [`ChatListener`].
///
/// Callbacks will be serialized (i.e. two calls will not come in at the same time), but may not
/// always happen on the same thread. Calls should be responded to promptly to avoid blocking later
/// messages.
///
/// # Safety
///
/// This type contains raw pointers. Code that constructs an instance of this type must ensure
/// memory safety assuming that
/// - the callback function pointer fields are called with `ctx` as an argument;
/// - the `destroy` function pointer field is called with `ctx` as an argument;
/// - no function pointer fields are called after `destroy` is called.
#[repr(C)]
pub struct FfiChatListenerStruct {
    ctx: *mut c_void,
    received_incoming_message: ReceivedIncomingMessage,
    received_queue_empty: ReceivedQueueEmpty,
    received_alerts: ReceivedAlerts,
    connection_interrupted: ConnectionInterrupted,
    destroy: DestroyChatListener,
}

impl FfiChatListenerStruct {
    /// Turns `self` into a type-erased [`ChatListener`].
    ///
    /// Takes ownership of the memory behind [`FfiChatListenerStruct::ctx`] and
    /// produces a type-erased `ChatListener` that implements the trait methods
    /// by delegating to the respective callbacks in `self`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this method is called at most once on an
    /// `FfiChatListenerStruct`.
    pub(crate) unsafe fn make_listener(&self) -> Box<dyn ChatListener + UnwindSafe> {
        let FfiChatListenerStruct {
            ctx,
            received_incoming_message,
            received_queue_empty,
            received_alerts,
            connection_interrupted,
            destroy,
        } = *self;
        Box::new(ChatListenerStruct(FfiChatListenerStruct {
            ctx,
            received_incoming_message,
            received_queue_empty,
            received_alerts,
            connection_interrupted,
            destroy,
        }))
    }
}

// SAFETY: Chat listeners are used from multiple threads. It's up to the creator of the C struct to
// make sure `ctx` is appropriate for this.
unsafe impl Send for FfiChatListenerStruct {}

struct ChatListenerStruct(FfiChatListenerStruct);

impl Drop for ChatListenerStruct {
    fn drop(&mut self) {
        (self.0.destroy)(self.0.ctx);
    }
}

impl ChatListener for ChatListenerStruct {
    fn received_incoming_message(
        &mut self,
        envelope: Bytes,
        timestamp: Timestamp,
        ack: ServerMessageAck,
    ) {
        (self.0.received_incoming_message)(
            self.0.ctx,
            envelope
                .convert_into()
                .expect("Vec<u8> conversion is infallible"),
            timestamp.epoch_millis(),
            ack.convert_into()
                .expect("bridge_as_handle conversion is infallible")
                .into_inner(),
        )
    }

    fn received_queue_empty(&mut self) {
        (self.0.received_queue_empty)(self.0.ctx)
    }

    fn received_alerts(&mut self, alerts: Vec<String>) {
        (self.0.received_alerts)(
            self.0.ctx,
            alerts
                .into_boxed_slice()
                .convert_into()
                .expect("Box<[String]> conversion is infallible"),
        )
    }

    fn connection_interrupted(&mut self, disconnect_cause: DisconnectCause) {
        let error = match disconnect_cause {
            DisconnectCause::LocalDisconnect => None,
            DisconnectCause::Error(c) => Some(Box::new(SignalFfiError::from(c))),
        };
        (self.0.connection_interrupted)(
            self.0.ctx,
            error.map_or(std::ptr::null_mut(), Box::into_raw),
        )
    }
}

type GetConnectChatConnectionManager = extern "C" fn(ctx: *mut c_void) -> *const ConnectionManager;
type DestroyConnectChatBridge = extern "C" fn(ctx: *mut c_void);

/// A ref-counting pointer to a [`ConnectionManager`] and a callback to
/// decrement the count.
#[repr(C)]
pub struct FfiConnectChatBridgeStruct {
    ctx: *mut c_void,
    get_connection_manager: GetConnectChatConnectionManager,
    destroy: DestroyConnectChatBridge,
}

/// Rust version of [`FfiConnectChatBridgeStruct`] that will decrement the count
/// on drop.
pub struct FfiConnectChatBridge {
    ctx: *mut c_void,
    connection_manager: *const ConnectionManager,
    destroy: DestroyConnectChatBridge,
}

impl FfiConnectChatBridge {
    pub(crate) fn new(bridge: &FfiConnectChatBridgeStruct) -> Result<Self, NullPointerError> {
        let FfiConnectChatBridgeStruct {
            ctx,
            get_connection_manager,
            destroy,
        } = bridge;
        let connection_manager =
            unsafe { get_connection_manager(*ctx).as_ref() }.ok_or(NullPointerError)?;
        Ok(Self {
            ctx: *ctx,
            connection_manager,
            destroy: *destroy,
        })
    }
}

impl Drop for FfiConnectChatBridge {
    fn drop(&mut self) {
        let Self {
            ctx,
            connection_manager: _,
            destroy,
        } = self;
        destroy(*ctx);
    }
}

// SAFETY: This bridge can be used from multiple threads. It's up to the creator
// of the C struct to make sure `ctx` is appropriate for this.
unsafe impl Send for FfiConnectChatBridge {}
unsafe impl Sync for FfiConnectChatBridge {}

struct FfiConnectChat {
    bridge: FfiConnectChatBridge,
    runtime: tokio::runtime::Handle,
}

impl ConnectUnauthChat for FfiConnectChat {
    fn connect_chat(
        &self,
        on_disconnect: tokio::sync::oneshot::Sender<std::convert::Infallible>,
    ) -> BoxFuture<'_, Result<Unauth<ChatConnection>, ConnectError>> {
        let Self {
            bridge:
                FfiConnectChatBridge {
                    ctx: _,
                    connection_manager,
                    destroy: _,
                },
            runtime: tokio_runtime,
        } = self;
        // Safety: the connection manager was already checked for validity and
        // the reference will remain valid as long as `self` isn't dropped, and
        // that can't happen until the returned future is dropped.
        let connection_manager = unsafe { &**connection_manager };
        let connect = crate::net::chat::connect_registration_chat(
            tokio_runtime,
            connection_manager,
            on_disconnect,
        );
        connect.boxed()
    }
}

impl ConnectChatBridge for FfiConnectChatBridge {
    fn create_chat_connector(
        self: Box<Self>,
        runtime: tokio::runtime::Handle,
    ) -> Box<dyn ConnectUnauthChat + Send + Sync + UnwindSafe> {
        Box::new(FfiConnectChat {
            bridge: *self,
            runtime,
        })
    }
}
