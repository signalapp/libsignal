//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ffi::{c_uchar, c_void};
use std::panic::UnwindSafe;

use libsignal_net::chat::server_requests::DisconnectCause;

use super::*;
use crate::net::chat::{ChatListener, ServerMessageAck};

type ReceivedIncomingMessage = extern "C" fn(
    ctx: *mut c_void,
    envelope: OwnedBufferOf<c_uchar>,
    timestamp_millis: u64,
    cleanup: *mut ServerMessageAck,
);
type ReceivedQueueEmpty = extern "C" fn(ctx: *mut c_void);
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
            connection_interrupted,
            destroy,
        } = *self;
        Box::new(ChatListenerStruct(FfiChatListenerStruct {
            ctx,
            received_incoming_message,
            received_queue_empty,
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
        envelope: Vec<u8>,
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
