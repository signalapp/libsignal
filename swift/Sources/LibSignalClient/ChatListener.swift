//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public protocol ChatListener: AnyObject {
    /// Called when the server delivers an incoming message to the client.
    ///
    /// `serverDeliveryTimestamp` is in milliseconds.
    ///
    /// If `sendAck` is not called, the server will leave this message in the message queue and
    /// attempt to deliver it again in the future.
    func chatService(_ chat: ChatService, didReceiveIncomingMessage envelope: Data, serverDeliveryTimestamp: UInt64, sendAck: @escaping () async throws -> Void)

    /// Called when the server indicates that there are no further messages in the message queue.
    ///
    /// Note that further messages may still be delivered; this merely indicates that all messages
    /// that were in the queue
    ///
    /// The default implementation of this method does nothing.
    func chatServiceDidReceiveQueueEmpty(_ chat: ChatService)
}

extension ChatListener {
    func chatServiceDidReceiveQueueEmpty(_: ChatService) {}
}

internal class ChatListenerBridge {
    private class AckHandleOwner: NativeHandleOwner {
        override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
            signal_server_message_ack_destroy(handle)
        }
    }

    weak var chatService: ChatService?
    let chatListener: ChatListener

    init(chatService: ChatService, chatListener: ChatListener) {
        self.chatService = chatService
        self.chatListener = chatListener
    }

    /// Creates an **owned** callback struct from this object.
    ///
    /// The resulting struct must eventually have its `destroy` callback invoked with its `ctx` as argument,
    /// or the ChatListenerBridge object used to construct it (`self`) will be leaked.
    func makeListenerStruct() -> SignalFfiChatListenerStruct {
        let receivedIncomingMessage: SignalReceivedIncomingMessage = { rawCtx, envelope, timestamp, ackHandle in
            defer { signal_free_buffer(envelope.base, envelope.length) }
            let ackHandleOwner = AckHandleOwner(owned: ackHandle!)

            let bridge = Unmanaged<ChatListenerBridge>.fromOpaque(rawCtx!).takeUnretainedValue()
            guard let chatService = bridge.chatService else {
                return
            }

            let envelopeData = Data(bytes: envelope.base, count: envelope.length)
            bridge.chatListener.chatService(chatService, didReceiveIncomingMessage: envelopeData, serverDeliveryTimestamp: timestamp) {
                _ = try await chatService.tokioAsyncContext.invokeAsyncFunction { promise, asyncContext in
                    ackHandleOwner.withNativeHandle { ackHandle in
                        signal_server_message_ack_send(promise, asyncContext, ackHandle)
                    }
                }
            }
        }
        let receivedQueueEmpty: SignalReceivedQueueEmpty = { rawCtx in
            let bridge = Unmanaged<ChatListenerBridge>.fromOpaque(rawCtx!).takeUnretainedValue()
            guard let chatService = bridge.chatService else {
                return
            }

            bridge.chatListener.chatServiceDidReceiveQueueEmpty(chatService)
        }

        return .init(
            ctx: Unmanaged.passRetained(self).toOpaque(),
            received_incoming_message: receivedIncomingMessage,
            received_queue_empty: receivedQueueEmpty,
            destroy: { rawCtx in
                _ = Unmanaged<AnyObject>.fromOpaque(rawCtx!).takeRetainedValue()
            }
        )
    }
}
