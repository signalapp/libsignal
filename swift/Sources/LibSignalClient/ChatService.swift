//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// Common interface for ongoing communication channels with the Chat Service.
public protocol ChatService: AnyObject {
    /// Initiates establishing of the underlying authenticated connection to the Chat Service. Once
    /// the service is connected, all the requests will be using the established connection. Also,
    /// if the connection is lost for any reason other than the call to ``disconnect()``, an
    /// automatic reconnect attempt will be made.
    ///
    /// Specific subclasses may have more information on the types of errors produced by `connect()`,
    /// as well as additional preconditions that should be satisfied.
    @discardableResult
    func connect() async throws -> DebugInfo

    /// Initiates termination of the underlying connection to the Chat Service. After the service is
    /// disconnected, it will not attempt to automatically reconnect until you call ``connect()``.
    ///
    /// Note: the same `ChatService` can be reused after `disconnect()` was called.
    ///
    /// Returns when the disconnection is complete.
    func disconnect() async throws

    /// Sends a request to the Chat Service.
    ///
    /// - Throws: ``SignalError/chatServiceInactive(_:)`` if you haven't called ``connect()``
    /// - Throws: Other ``SignalError``s for other kinds of failures.
    /// - SeeAlso: ``send(_:)``
    func send(_ request: Request) async throws -> Response

    /// Sends a request to the Chat Service.
    ///
    /// In addition to the response, an object containing debug information about the request flow
    /// is returned.
    ///
    /// - Throws: ``SignalError/chatServiceInactive(_:)`` if you haven't called ``connect()``
    /// - Throws: Other ``SignalError``s for other kinds of failures.
    /// - SeeAlso: ``send(_:)``
    func sendAndDebug(_ request: Request) async throws -> (Response, DebugInfo)
}

extension ChatService {
    public typealias Request = ChatRequest
    public typealias Response = ChatResponse
    public typealias DebugInfo = ChatServiceDebugInfo
}

/// Represents an API of authenticated communication with the Chat Service.
///
/// An instance of this object is obtained via call to ``Net/createAuthenticatedChatService(username:password:receiveStories:)``.
public class AuthenticatedChatService: NativeHandleOwner, ChatService {
    internal let tokioAsyncContext: TokioAsyncContext

    internal init(tokioAsyncContext: TokioAsyncContext, connectionManager: ConnectionManager, username: String, password: String, receiveStories: Bool) {
        var handle: OpaquePointer?
        connectionManager.withNativeHandle { connectionManager in
            failOnError(signal_chat_service_new_auth(&handle, connectionManager, username, password, receiveStories))
        }
        self.tokioAsyncContext = tokioAsyncContext
        super.init(owned: handle!)
    }

    internal required init(owned handle: OpaquePointer) {
        fatalError("should not be called directly for a ChatService")
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_auth_chat_destroy(handle)
    }

    /// Sets (or clears) the listener for server push messages.
    ///
    /// Takes ownership of the listener; be careful this doesn't lead to a reference cycle (unless the owner lives forever anyway).
    public func setListener(_ listener: (any ChatListener)?) {
        self.tokioAsyncContext.withNativeHandle { tokioAsyncContext in
            withNativeHandle { chatService in
                if let listener {
                    var listenerStruct = ChatListenerBridge(chatService: self, chatListener: listener).makeListenerStruct()
                    failOnError(signal_chat_service_set_listener_auth(tokioAsyncContext, chatService, &listenerStruct))
                } else {
                    failOnError(signal_chat_service_set_listener_auth(tokioAsyncContext, chatService, nil))
                }
            }
        }
    }

    /// Initiates establishing of the underlying authenticated connection to the Chat Service. Once
    /// the service is connected, all the requests will be using the established connection. Also,
    /// if the connection is lost for any reason other than the call to ``disconnect()``, an
    /// automatic reconnect attempt will be made.
    ///
    /// Calling this method will result in starting to accept incoming requests from the Chat
    /// Service. You should set a listener first using ``setListener(_:)``.
    ///
    /// - Throws: ``SignalError/appExpired(_:)`` if the current app version is too old (as judged by
    ///   the server).
    /// - Throws: ``SignalError/deviceDeregistered(_:)`` if the current device has been deregistered
    ///   or delinked.
    /// - Throws: ``SignalError/rateLimitedError(_:, _:)`` if the server
    ///   response indicates the request should be tried again after some time.
    /// - Throws: Other ``SignalError``s for other kinds of failures.
    @discardableResult
    public func connect() async throws -> DebugInfo {
        let rawDebugInfo = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                signal_chat_service_connect_auth(promise, tokioAsyncContext, chatService)
            }
        }
        return DebugInfo(consuming: rawDebugInfo)
    }

    /// Initiates termination of the underlying connection to the Chat Service. After the service is
    /// disconnected, it will not attempt to automatically reconnect until you call ``connect()``.
    ///
    /// Note: the same instance of `AuthenticatedChatService` can be reused after `disconnect()` was
    /// called.
    ///
    /// Returns when the disconnection is complete.
    public func disconnect() async throws {
        _ = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                signal_chat_service_disconnect_auth(promise, tokioAsyncContext, chatService)
            }
        }
    }

    /// Sends request to the Chat Service over an authenticated channel.
    ///
    /// - Throws: ``SignalError/chatServiceInactive(_:)`` if you haven't called ``connect()``
    /// - Throws: Other ``SignalError``s for other kinds of failures.
    /// - SeeAlso: ``sendAndDebug(_:)``
    public func send(_ request: Request) async throws -> Response {
        let internalRequest = try Request.InternalRequest(request)
        let timeoutMillis = request.timeoutMillis
        let rawResponse: SignalFfiChatResponse = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                internalRequest.withNativeHandle { request in
                    signal_chat_service_auth_send(promise, tokioAsyncContext, chatService, request, timeoutMillis)
                }
            }
        }
        return try Response(consuming: rawResponse)
    }

    /// Sends request to the Chat Service over an authenticated channel.
    ///
    /// In addition to the response, an object containing debug information about the request flow
    /// is returned.
    ///
    /// - Throws: ``SignalError/chatServiceInactive(_:)`` if you haven't called ``connect()``
    /// - Throws: Other ``SignalError``s for other kinds of failures.
    /// - SeeAlso: ``send(_:)``
    public func sendAndDebug(_ request: Request) async throws -> (Response, DebugInfo) {
        let internalRequest = try Request.InternalRequest(request)
        let timeoutMillis = request.timeoutMillis
        let rawResponse: SignalFfiResponseAndDebugInfo = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                internalRequest.withNativeHandle { request in
                    signal_chat_service_auth_send_and_debug(promise, tokioAsyncContext, chatService, request, timeoutMillis)
                }
            }
        }
        return (try Response(consuming: rawResponse.response), DebugInfo(consuming: rawResponse.debug_info))
    }
}

/// Represents an API of unauthenticated communication with the Chat Service.
///
/// An instance of this object is obtained via call to ``Net/createUnauthenticatedChatService()``.
public class UnauthenticatedChatService: NativeHandleOwner, ChatService {
    internal let tokioAsyncContext: TokioAsyncContext

    internal init(tokioAsyncContext: TokioAsyncContext, connectionManager: ConnectionManager) {
        var handle: OpaquePointer?
        connectionManager.withNativeHandle { connectionManager in
            failOnError(signal_chat_service_new_unauth(&handle, connectionManager))
        }
        self.tokioAsyncContext = tokioAsyncContext
        super.init(owned: handle!)
    }

    internal required init(owned handle: OpaquePointer) {
        fatalError("should not be called directly for a ChatService")
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_unauth_chat_destroy(handle)
    }

    /// Sets (or clears) the listener for connection events.
    ///
    /// Takes ownership of the listener; be careful this doesn't lead to a reference cycle (unless the owner lives forever anyway).
    public func setListener(_ listener: (any ConnectionEventsListener<UnauthenticatedChatService>)?) {
        self.tokioAsyncContext.withNativeHandle { tokioAsyncContext in
            withNativeHandle { chatService in
                if let listener {
                    var listenerStruct = UnauthConnectionEventsListenerBridge(chatService: self, listener: listener).makeListenerStruct()
                    failOnError(signal_chat_service_set_listener_unauth(tokioAsyncContext, chatService, &listenerStruct))
                } else {
                    failOnError(signal_chat_service_set_listener_unauth(tokioAsyncContext, chatService, nil))
                }
            }
        }
    }

    /// Initiates establishing of the underlying unauthenticated connection to the Chat Service. Once
    /// the service is connected, all the requests will be using the established connection. Also,
    /// if the connection is lost for any reason other than the call to ``disconnect()``, an
    /// automatic reconnect attempt will be made.
    ///
    /// - Throws: ``SignalError/appExpired(_:)`` if the current app version is too old (as judged by
    ///   the server).
    /// - Throws: ``SignalError/rateLimitedError(_:, _:)`` if the server
    ///   response indicates the request should be tried again after some time.
    /// - Throws: Other ``SignalError``s for other kinds of failures.
    @discardableResult
    public func connect() async throws -> DebugInfo {
        let rawDebugInfo = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                signal_chat_service_connect_unauth(promise, tokioAsyncContext, chatService)
            }
        }
        return DebugInfo(consuming: rawDebugInfo)
    }

    /// Initiates termination of the underlying connection to the Chat Service. After the service is
    /// disconnected, it will not attempt to automatically reconnect until you call ``connect()``.
    ///
    /// Note: the same instance of `UnauthenticatedChatService` can be reused after `disconnect()` was
    /// called.
    ///
    /// Returns when the disconnection is complete.
    public func disconnect() async throws {
        _ = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                signal_chat_service_disconnect_unauth(promise, tokioAsyncContext, chatService)
            }
        }
    }

    /// Sends request to the Chat Service over an unauthenticated channel.
    ///
    /// - Throws: ``SignalError/chatServiceInactive(_:)`` if you haven't called ``connect()``
    /// - Throws: Other ``SignalError``s for other kinds of failures.
    /// - SeeAlso: ``sendAndDebug(_:)``
    public func send(_ request: Request) async throws -> Response {
        let internalRequest = try Request.InternalRequest(request)
        let timeoutMillis = request.timeoutMillis
        let rawResponse: SignalFfiChatResponse = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                internalRequest.withNativeHandle { request in
                    signal_chat_service_unauth_send(promise, tokioAsyncContext, chatService, request, timeoutMillis)
                }
            }
        }
        return try Response(consuming: rawResponse)
    }

    /// Sends request to the Chat Service over an unauthenticated channel.
    ///
    /// In addition to the response, an object containing debug information about the request flow
    /// is returned.
    ///
    /// - Throws: ``SignalError/chatServiceInactive(_:)`` if you haven't called ``connect()``
    /// - Throws: Other ``SignalError``s for other kinds of failures.
    /// - SeeAlso: ``send(_:)``
    public func sendAndDebug(_ request: Request) async throws -> (Response, DebugInfo) {
        let internalRequest = try Request.InternalRequest(request)
        let timeoutMillis = request.timeoutMillis
        let rawResponse: SignalFfiResponseAndDebugInfo = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                internalRequest.withNativeHandle { request in
                    signal_chat_service_unauth_send_and_debug(promise, tokioAsyncContext, chatService, request, timeoutMillis)
                }
            }
        }
        return (try Response(consuming: rawResponse.response), DebugInfo(consuming: rawResponse.debug_info))
    }
}
