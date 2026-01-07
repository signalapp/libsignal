//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ffi::c_void;
use std::panic::UnwindSafe;

use futures_util::FutureExt as _;
use futures_util::future::BoxFuture;
use libsignal_net::chat::{ChatConnection, ConnectError};
use libsignal_net_chat::api::Unauth;
use libsignal_net_chat::registration::ConnectUnauthChat;

use super::*;
use crate::net::ConnectionManager;
// TODO: This re-export is because of the ffi_arg_type macro expecting all bridging structs to be
// under the ffi module; eventually we should be able to remove it.
pub use crate::net::chat::{FfiChatListenerStruct, FfiProvisioningListenerStruct};
use crate::net::registration::ConnectChatBridge;

// SAFETY: Chat listeners are used from multiple threads. It's up to the creator of the C struct to
// make sure `ctx` is appropriate for this.
unsafe impl Send for FfiChatListenerStruct {}
unsafe impl Send for FfiProvisioningListenerStruct {}

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
