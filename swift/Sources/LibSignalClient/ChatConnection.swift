//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public protocol ChatConnection: AnyObject {
    /// Initiates termination of the underlying connection to the Chat Service.
    ///
    /// Returns when the disconnection is complete.
    func disconnect() async throws

    /// Sends a request to the Chat Service.
    ///
    /// - Throws: ``SignalError``s for the various failure modes.
    func send(_ request: Request) async throws -> Response

    /// Produces information about the connection.
    func info() -> ConnectionInfo
}

public class ConnectionInfo: NativeHandleOwner, CustomStringConvertible {
    /// The local port used by the connection.
    public var localPort: UInt16 {
        withNativeHandle { connectionInfo in
            failOnError {
                try invokeFnReturningInteger {
                    signal_chat_connection_info_local_port($0, connectionInfo)
                }
            }
        }
    }

    /// The IP addressing version used by the connection.
    public var ipType: IpType {
        let rawValue = withNativeHandle { connectionInfo in
            failOnError {
                try invokeFnReturningInteger {
                    signal_chat_connection_info_ip_version($0, connectionInfo)
                }
            }
        }
        return IpType(rawValue: rawValue) ?? .unknown
    }

    /// A developer-facing description of the connection.
    public var description: String {
        withNativeHandle { connectionInfo in
            failOnError {
                try invokeFnReturningString {
                    signal_chat_connection_info_description($0, connectionInfo)
                }
            }
        }
    }
}

extension ChatConnection {
    public typealias Request = ChatRequest
    public typealias Response = ChatResponse
    public typealias DebugInfo = ChatServiceDebugInfo
}

/// Represents an authenticated connection to the Chat Service.
///
/// An instance of this object is obtained via call to ``Net/connectAuthenticatedChat(username:password:receiveStories:)``.
/// Before an obtained instance can be used, it must be started by calling ``AuthenticatedChatConnection/start(listener:)``.
public class AuthenticatedChatConnection: NativeHandleOwner, ChatConnection {
    internal let tokioAsyncContext: TokioAsyncContext

    /// Initiates establishing of the underlying unauthenticated connection to the Chat Service. Once
    /// the connection is established, the returned object can be used to send and receive messages
    /// after ``AuthenticatedChatConnection/start(listener:)`` is called.
    internal init(tokioAsyncContext: TokioAsyncContext, connectionManager: ConnectionManager, username: String, password: String, receiveStories: Bool) async throws {
        let nativeHandle = try await tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            connectionManager.withNativeHandle { connectionManager in
                signal_authenticated_chat_connection_connect(promise, tokioAsyncContext, connectionManager, username, password, receiveStories)
            }
        }
        self.tokioAsyncContext = tokioAsyncContext
        super.init(owned: nativeHandle)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_authenticated_chat_connection_destroy(handle)
    }

    internal required init(owned handle: OpaquePointer) {
        fatalError("should not be called directly for a ChatConnection")
    }

    /// Sets the listener and starts the background thread that handles communication.
    ///
    /// This must be called exactly once for the ``AuthenticatedChatConnection``
    /// to be used. Before this method is called, no messages can be sent or
    /// received.
    public func start(listener: any ChatConnectionListener) {
        withNativeHandle { chatConnection in
            var listenerStruct = ChatListenerBridge(chatConnection: self, chatListener: listener).makeListenerStruct()
            failOnError(signal_authenticated_chat_connection_init_listener(chatConnection, &listenerStruct))
        }
    }

    /// Initiates termination of the underlying connection to the Chat Service.
    ///
    /// Returns when the disconnection is complete.
    public func disconnect() async throws {
        _ = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatConnection in
                signal_authenticated_chat_connection_disconnect(promise, tokioAsyncContext, chatConnection)
            }
        }
    }

    /// Sends a request to the Chat Service over an authenticated channel.
    ///
    /// - Throws: ``SignalError/chatServiceInactive(_:)`` if you haven't called ``start()``
    /// - Throws: Other ``SignalError``s for other kinds of failures.
    public func send(_ request: Request) async throws -> Response {
        let internalRequest = try Request.InternalRequest(request)
        let timeoutMillis = request.timeoutMillis
        let rawResponse: SignalFfiChatResponse = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                internalRequest.withNativeHandle { request in
                    signal_authenticated_chat_connection_send(promise, tokioAsyncContext, chatService, request, timeoutMillis)
                }
            }
        }
        return try Response(consuming: rawResponse)
    }

    /// Returns an object representing information about the connection.
    public func info() -> ConnectionInfo {
        withNativeHandle { chatConnection in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_authenticated_chat_connection_info($0, chatConnection)
                }
            }
        }
    }
}

/// Represents an unauthenticated connection to the Chat Service.
///
/// An instance of this object is obtained via call to ``Net/connectUnauthenticatedChat()``.
/// Before an obtained instance can be used, it must be started by calling ``UnauthenticatedChatConnection/start(listener:)``.
public class UnauthenticatedChatConnection: NativeHandleOwner, ChatConnection {
    internal let tokioAsyncContext: TokioAsyncContext

    /// Initiates establishing of the underlying unauthenticated connection to
    /// the Chat Service. Once the connection is established, the returned
    /// object can be used to send and receive messages after
    /// ``UnauthenticatedChatConnection/start(listener:)`` is called.
    internal init(tokioAsyncContext: TokioAsyncContext, connectionManager: ConnectionManager) async throws {
        let nativeHandle = try await tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            connectionManager.withNativeHandle { connectionManager in
                signal_unauthenticated_chat_connection_connect(promise, tokioAsyncContext, connectionManager)
            }
        }
        self.tokioAsyncContext = tokioAsyncContext
        super.init(owned: nativeHandle)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_unauthenticated_chat_connection_destroy(handle)
    }

    internal required init(owned handle: OpaquePointer) {
        fatalError("should not be called directly for a ChatConnection")
    }

    /// Sets the listener and starts the background thread that handles communication.
    ///
    /// This must be called exactly once for the
    /// ``UnauthenticatedChatConnection`` to be used. Before this method is
    /// called, no messages can be sent or received.
    public func start(listener: any ConnectionEventsListener<UnauthenticatedChatConnection>) {
        withNativeHandle { chatConnection in
            var listenerStruct = UnauthConnectionEventsListenerBridge(chatConnection: self, listener: listener).makeListenerStruct()
            failOnError(signal_unauthenticated_chat_connection_init_listener(chatConnection, &listenerStruct))
        }
    }

    /// Initiates termination of the underlying connection to the Chat Service.
    ///
    /// Returns when the disconnection is complete.
    public func disconnect() async throws {
        _ = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatConnection in
                signal_unauthenticated_chat_connection_disconnect(promise, tokioAsyncContext, chatConnection)
            }
        }
    }

    /// Sends request to the Chat Service over an authenticated channel.
    ///
    /// - Throws: ``SignalError/chatServiceInactive(_:)`` if you haven't called ``start()``.
    /// - Throws: Other ``SignalError``s for other kinds of failures.
    public func send(_ request: Request) async throws -> Response {
        let internalRequest = try Request.InternalRequest(request)
        let timeoutMillis = request.timeoutMillis
        let rawResponse: SignalFfiChatResponse = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                internalRequest.withNativeHandle { request in
                    signal_unauthenticated_chat_connection_send(promise, tokioAsyncContext, chatService, request, timeoutMillis)
                }
            }
        }
        return try Response(consuming: rawResponse)
    }

    /// Returns an object representing information about the connection.
    public func info() -> ConnectionInfo {
        withNativeHandle { chatConnection in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_authenticated_chat_connection_info($0, chatConnection)
                }
            }
        }
    }
}
