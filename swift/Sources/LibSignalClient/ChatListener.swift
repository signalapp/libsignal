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

@available(*, deprecated, renamed: "ChatServiceListener")
public typealias ChatListener = ChatServiceListener

public protocol ChatServiceListener: ConnectionEventsListener<AuthenticatedChatService> {
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

extension ChatServiceListener {
    public func chatServiceDidReceiveQueueEmpty(_: AuthenticatedChatService) {}
}

public protocol ChatConnectionListener: ConnectionEventsListener<AuthenticatedChatConnection> {
    /// Called when the server delivers an incoming message to the client.
    ///
    /// `serverDeliveryTimestamp` is in milliseconds.
    ///
    /// If `sendAck` is not called, the server will leave this message in the message queue and
    /// attempt to deliver it again in the future.
    func chatConnection(_ chat: AuthenticatedChatConnection, didReceiveIncomingMessage envelope: Data, serverDeliveryTimestamp: UInt64, sendAck: @escaping () async throws -> Void)

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

internal struct Weak<T: AnyObject> {
    weak var inner: T?
    init(_ inner: T) {
        self.inner = inner
    }
}

private protocol ChatListenerConnection {
    var tokioAsyncContext: TokioAsyncContext { get }
}

extension AuthenticatedChatService: ChatListenerConnection {}

extension AuthenticatedChatConnection: ChatListenerConnection {}

internal class ChatListenerBridge {
    private class AckHandleOwner: NativeHandleOwner<SignalMutPointerServerMessageAck> {
        override class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerServerMessageAck>) -> SignalFfiErrorRef? {
            signal_server_message_ack_destroy(handle.pointer)
        }
    }

    fileprivate enum Inner {
        case service(Weak<AuthenticatedChatService>, any ChatServiceListener)
        case connection(Weak<AuthenticatedChatConnection>, any ChatConnectionListener)
    }

    private var inner: Inner

    internal init(
        chatService: AuthenticatedChatService,
        chatListener: any ChatServiceListener
    ) {
        self.inner = .service(Weak(chatService), chatListener)
    }

    internal init(
        chatConnection: AuthenticatedChatConnection,
        chatListener: any ChatConnectionListener
    ) {
        self.inner = .connection(Weak(chatConnection), chatListener)
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
            switch bridge.inner {
            case .service(let chatService, let chatListener):
                guard let chatService = chatService.inner else {
                    return
                }

                let envelopeData = Data(bytes: envelope.base, count: envelope.length)
                chatListener.chatService(
                    chatService, didReceiveIncomingMessage: envelopeData,
                    serverDeliveryTimestamp: timestamp
                ) {
                    _ = try await chatService.tokioAsyncContext.invokeAsyncFunction { promise, asyncContext in
                        ackHandleOwner.withNativeHandle { ackHandle in
                            signal_server_message_ack_send(promise, asyncContext.const(), ackHandle.const())
                        }
                    }
                }
            case .connection(let chatService, let chatListener):
                guard let chatService = chatService.inner else {
                    return
                }

                let envelopeData = Data(bytes: envelope.base, count: envelope.length)
                chatListener.chatConnection(
                    chatService, didReceiveIncomingMessage: envelopeData,
                    serverDeliveryTimestamp: timestamp
                ) {
                    _ = try await chatService.tokioAsyncContext.invokeAsyncFunction { promise, asyncContext in
                        ackHandleOwner.withNativeHandle { ackHandle in
                            signal_server_message_ack_send(promise, asyncContext.const(), ackHandle.const())
                        }
                    }
                }
            }
        }

        let receivedQueueEmpty: SignalReceivedQueueEmpty = { rawCtx in
            let bridge = Unmanaged<ChatListenerBridge>.fromOpaque(rawCtx!).takeUnretainedValue()
            switch bridge.inner {
            case .service(let chatService, let chatListener):
                guard let chatService = chatService.inner else {
                    return
                }

                chatListener.chatServiceDidReceiveQueueEmpty(chatService)
            case .connection(let chatService, let chatListener):
                guard let chatService = chatService.inner else {
                    return
                }

                chatListener.chatConnectionDidReceiveQueueEmpty(chatService)
            }
        }
        let connectionInterrupted: SignalConnectionInterrupted = { rawCtx, maybeError in
            let bridge = Unmanaged<ChatListenerBridge>.fromOpaque(rawCtx!).takeUnretainedValue()
            switch bridge.inner {
            case .service(let chatService, let chatListener):
                guard let chatService = chatService.inner else {
                    return
                }

                let error = convertError(maybeError)

                chatListener.connectionWasInterrupted(chatService, error: error)
            case .connection(let chatService, let chatListener):
                guard let chatService = chatService.inner else {
                    return
                }

                let error = convertError(maybeError)
                chatListener.connectionWasInterrupted(chatService, error: error)
            }
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
    private enum Inner {
        case service(
            Weak<UnauthenticatedChatService>,
            any ConnectionEventsListener<UnauthenticatedChatService>
        )
        case connection(Weak<UnauthenticatedChatConnection>, any ConnectionEventsListener<UnauthenticatedChatConnection>)
    }

    private let inner: Inner

    init(
        chatService: UnauthenticatedChatService,
        listener: any ConnectionEventsListener<UnauthenticatedChatService>
    ) {
        self.inner = .service(Weak(chatService), listener)
    }

    init(
        chatConnection: UnauthenticatedChatConnection,
        listener: any ConnectionEventsListener<UnauthenticatedChatConnection>
    ) {
        self.inner = .connection(Weak(chatConnection), listener)
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

            switch bridge.inner {
            case .service(let service, let listener):
                guard let chatService = service.inner else {
                    return
                }

                let error = convertError(maybeError)

                listener.connectionWasInterrupted(chatService, error: error)
            case .connection(let service, let listener):
                guard let chatService = service.inner else {
                    return
                }

                let error = convertError(maybeError)

                listener.connectionWasInterrupted(chatService, error: error)
            }
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
