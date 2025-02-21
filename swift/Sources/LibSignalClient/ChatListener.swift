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

public protocol ChatConnectionListener: ConnectionEventsListener<AuthenticatedChatConnection> {
    /// Called when the server delivers an incoming message to the client.
    ///
    /// `serverDeliveryTimestamp` is in milliseconds.
    ///
    /// If `sendAck` is not called, the server will leave this message in the message queue and
    /// attempt to deliver it again in the future.
    func chatConnection(_ chat: AuthenticatedChatConnection, didReceiveIncomingMessage envelope: Data, serverDeliveryTimestamp: UInt64, sendAck: @escaping () throws -> Void)

    /// Called when the server indicates that there are no further messages in the message queue.
    ///
    /// Note that further messages may still be delivered; this merely indicates that all messages
    /// that were in the queue *when the connection was established* have been delivered.
    ///
    /// The default implementation of this method does nothing.
    func chatConnectionDidReceiveQueueEmpty(_ chat: AuthenticatedChatConnection)
}

extension ChatConnectionListener {
    public func chatConnectionDidReceiveQueueEmpty(_: AuthenticatedChatConnection) {}
}

private protocol ChatListenerConnection {
    var tokioAsyncContext: TokioAsyncContext { get }
}

extension AuthenticatedChatConnection: ChatListenerConnection {}

internal class ChatListenerBridge {
    private class AckHandleOwner: NativeHandleOwner<SignalMutPointerServerMessageAck> {
        override class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerServerMessageAck>) -> SignalFfiErrorRef? {
            signal_server_message_ack_destroy(handle.pointer)
        }
    }

    private weak var chatConnection: AuthenticatedChatConnection?
    private var chatListener: any ChatConnectionListener

    internal init(
        chatConnection: AuthenticatedChatConnection,
        chatListener: any ChatConnectionListener
    ) {
        self.chatConnection = chatConnection
        self.chatListener = chatListener
    }

    internal init(
        chatConnectionListener: any ChatConnectionListener
    ) {
        self.chatListener = chatConnectionListener
    }

    internal func setConnection(chatConnection: AuthenticatedChatConnection) {
        self.chatConnection = chatConnection
    }

    /// Creates an **owned** callback struct from this object.
    ///
    /// The resulting struct must eventually have its `destroy` callback invoked with its `ctx` as argument,
    /// or the ChatListenerBridge object used to construct it (`self`) will be leaked.
    func makeListenerStruct() -> SignalFfiChatListenerStruct {
        let receivedIncomingMessage: SignalReceivedIncomingMessage = { rawCtx, envelope, timestamp, ackHandle in
            defer { signal_free_buffer(envelope.base, envelope.length) }
            let bridge = Unmanaged<ChatListenerBridge>.fromOpaque(rawCtx!).takeUnretainedValue()

            let ackHandleOwner = AckHandleOwner(owned: NonNull(ackHandle)!)
            guard let chatConnection = bridge.chatConnection else {
                return
            }

            let envelopeData = Data(bytes: envelope.base, count: envelope.length)
            bridge.chatListener.chatConnection(
                chatConnection, didReceiveIncomingMessage: envelopeData,
                serverDeliveryTimestamp: timestamp
            ) { _ = ackHandleOwner.withNativeHandle { ackHandle in signal_server_message_ack_send(ackHandle.const()) } }
        }

        let receivedQueueEmpty: SignalReceivedQueueEmpty = { rawCtx in
            let bridge = Unmanaged<ChatListenerBridge>.fromOpaque(rawCtx!).takeUnretainedValue()
            guard let chatConnection = bridge.chatConnection else {
                return
            }

            bridge.chatListener.chatConnectionDidReceiveQueueEmpty(chatConnection)
        }
        let connectionInterrupted: SignalConnectionInterrupted = { rawCtx, maybeError in
            let bridge = Unmanaged<ChatListenerBridge>.fromOpaque(rawCtx!).takeUnretainedValue()
            guard let chatConnection = bridge.chatConnection else {
                return
            }

            let error = convertError(maybeError)
            bridge.chatListener.connectionWasInterrupted(chatConnection, error: error)
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

extension SignalMutPointerServerMessageAck: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerServerMessageAck

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> SignalConstPointerServerMessageAck {
        SignalConstPointerServerMessageAck(raw: self.raw)
    }
}

extension SignalConstPointerServerMessageAck: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

internal final class UnauthConnectionEventsListenerBridge {
    private weak var chatConnection: UnauthenticatedChatConnection?
    private let chatListener: any ConnectionEventsListener<UnauthenticatedChatConnection>

    init(
        chatConnection: UnauthenticatedChatConnection,
        listener: any ConnectionEventsListener<UnauthenticatedChatConnection>
    ) {
        self.chatConnection = chatConnection
        self.chatListener = listener
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
            let bridge = Unmanaged<UnauthConnectionEventsListenerBridge>.fromOpaque(rawCtx!)
                .takeUnretainedValue()

            guard let chatConnection = bridge.chatConnection else {
                return
            }

            let error = convertError(maybeError)

            bridge.chatListener.connectionWasInterrupted(chatConnection, error: error)
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
