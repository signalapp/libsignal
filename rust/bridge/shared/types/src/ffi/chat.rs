//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ffi::{c_uchar, c_void};

use libsignal_net::chat::ChatServiceError;

use super::*;
use crate::net::chat::{ChatListener, MakeChatListener, ServerMessageAck};

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
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiChatListenerStruct {
    ctx: *mut c_void,
    received_incoming_message: ReceivedIncomingMessage,
    received_queue_empty: ReceivedQueueEmpty,
    connection_interrupted: ConnectionInterrupted,
    destroy: DestroyChatListener,
}

pub type FfiMakeChatListenerStruct = FfiChatListenerStruct;

// SAFETY: Chat listeners are used from multiple threads. It's up to the creator of the C struct to
// make sure `ctx` is appropriate for this.
unsafe impl Send for FfiChatListenerStruct {}

impl MakeChatListener for &FfiChatListenerStruct {
    fn make_listener(&self) -> Box<dyn ChatListener> {
        Box::new(ChatListenerStruct(**self))
    }
}

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
                .expect("bridge_as_handle conversion is infallible"),
        )
    }

    fn received_queue_empty(&mut self) {
        (self.0.received_queue_empty)(self.0.ctx)
    }

    fn connection_interrupted(&mut self, disconnect_cause: ChatServiceError) {
        let error = match disconnect_cause {
            ChatServiceError::ServiceIntentionallyDisconnected => None,
            c => Some(Box::new(SignalFfiError::from(c))),
        };
        (self.0.connection_interrupted)(
            self.0.ctx,
            error.map_or(std::ptr::null_mut(), Box::into_raw),
        )
    }
}
