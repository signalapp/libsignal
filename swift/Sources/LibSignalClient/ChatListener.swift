//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public protocol ConnectionEventsListener<Service>: AnyObject {
    associatedtype Service: AnyObject

    /// Called when the client gets disconnected from the server.
    ///
    /// This includes both deliberate disconnects as well as unexpected socket closures.
    func connectionWasInterrupted(_ service: Service, error: Error?)
}

public protocol ChatListener: ConnectionEventsListener<AuthenticatedChatService> {
    /// Called when the server delivers an incoming message to the client.
    ///
    /// `serverDeliveryTimestamp` is in milliseconds.
    ///
    /// If `sendAck` is not called, the server will leave this message in the message queue and
    /// attempt to deliver it again in the future.
    func chatService(_ chat: AuthenticatedChatService, didReceiveIncomingMessage envelope: Data, serverDeliveryTimestamp: UInt64, sendAck: @escaping () async throws -> Void)

    /// Called when the server indicates that there are no further messages in the message queue.
    ///
    /// Note that further messages may still be delivered; this merely indicates that all messages
    /// that were in the queue *when the connection was established* have been delivered.
    ///
    /// The default implementation of this method does nothing.
    func chatServiceDidReceiveQueueEmpty(_ chat: AuthenticatedChatService)
}

extension ChatListener {
    public func chatServiceDidReceiveQueueEmpty(_: AuthenticatedChatService) {}
}

internal class ChatListenerBridge {
    private class AckHandleOwner: NativeHandleOwner {
        override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
            signal_server_message_ack_destroy(handle)
        }
    }

    weak var chatService: AuthenticatedChatService?
    let chatListener: any ChatListener

    init(chatService: AuthenticatedChatService, chatListener: any ChatListener) {
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
        let connectionInterrupted: SignalConnectionInterrupted = { rawCtx, maybeError in
            let bridge = Unmanaged<ChatListenerBridge>.fromOpaque(rawCtx!).takeUnretainedValue()
            guard let chatService = bridge.chatService else {
                return
            }

            let error = convertError(maybeError)

            bridge.chatListener.connectionWasInterrupted(chatService, error: error)
        }

        return .init(
            ctx: Unmanaged.passRetained(self).toOpaque(),
            received_incoming_message: receivedIncomingMessage,
            received_queue_empty: receivedQueueEmpty,
            connection_interrupted: connectionInterrupted,
            destroy: { rawCtx in
                _ = Unmanaged<AnyObject>.fromOpaque(rawCtx!).takeRetainedValue()
            }
        )
    }
}

internal final class UnauthConnectionEventsListenerBridge {
    weak var chatService: UnauthenticatedChatService?
    let listener: any ConnectionEventsListener<UnauthenticatedChatService>

    init(chatService: UnauthenticatedChatService, listener: any ConnectionEventsListener<UnauthenticatedChatService>) {
        self.chatService = chatService
        self.listener = listener
    }

    /// Creates an **owned** callback struct from this object.
    ///
    /// The resulting struct must eventually have its `destroy` callback invoked with its `ctx` as argument,
    /// or the ChatListenerBridge object used to construct it (`self`) will be leaked.
    func makeListenerStruct() -> SignalFfiChatListenerStruct {
        let receivedIncomingMessage: SignalReceivedIncomingMessage = { _, _, _, _ in
            fatalError("not used for the unauth listener")
        }
        let receivedQueueEmpty: SignalReceivedQueueEmpty = { _ in
            fatalError("not used for the unauth listener")
        }
        let connectionInterrupted: SignalConnectionInterrupted = { rawCtx, maybeError in
            let bridge = Unmanaged<UnauthConnectionEventsListenerBridge>.fromOpaque(rawCtx!).takeUnretainedValue()
            guard let chatService = bridge.chatService else {
                return
            }

            let error = convertError(maybeError)

            bridge.listener.connectionWasInterrupted(chatService, error: error)
        }

        return .init(
            ctx: Unmanaged.passRetained(self).toOpaque(),
            received_incoming_message: receivedIncomingMessage,
            received_queue_empty: receivedQueueEmpty,
            connection_interrupted: connectionInterrupted,
            destroy: { rawCtx in
                _ = Unmanaged<AnyObject>.fromOpaque(rawCtx!).takeRetainedValue()
            }
        )
    }
}
