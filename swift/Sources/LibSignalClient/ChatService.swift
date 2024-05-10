//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum IpType: UInt8 {
    // Must be kept in sync with libsignal-net's IpType.
    case unknown, ipv4, ipv6
}

public protocol ChatListener: AnyObject {
    func chatService(_ chat: ChatService, didReceiveIncomingMessage envelope: Data, serverDeliveryTimestamp: UInt64, sendAck: () async throws -> Void)
    func chatServiceDidReceiveQueueEmpty(_ chat: ChatService)
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

/// Represents an API of communication with the Chat Service.
///
/// An instance of this object is obtained via call to ``Net/createChatService(username:password:)``.
public class ChatService: NativeHandleOwner {
    public struct Request: Equatable {
        public var method: String
        public var pathAndQuery: String
        public var headers: [String: String]
        public var body: Data?
        public var timeout: TimeInterval

        public init(method: String, pathAndQuery: String, headers: [String: String] = [:], body: Data? = nil, timeout: TimeInterval) {
            self.method = method
            self.pathAndQuery = pathAndQuery
            self.headers = headers
            self.body = body
            self.timeout = timeout
        }

        fileprivate var timeoutMillis: UInt32 {
            let timeoutMillisFloat: Double = 1000 * self.timeout
            if timeoutMillisFloat > Double(UInt32.max) {
                return .max
            } else if timeoutMillisFloat < 0 {
                // A bad idea, but one that won't crash.
                return 0
            } else {
                return UInt32(timeoutMillisFloat)
            }
        }
    }

    public struct Response: Equatable {
        public var status: UInt16
        public var message: String
        public var headers: [String: String]
        public var body: Data

        public init(status: UInt16, message: String = "", headers: [String: String] = [:], body: Data = Data()) {
            self.status = status
            self.message = message
            self.headers = headers
            self.body = body
        }

        // Exposed for testing.
        internal init(consuming rawResponse: SignalFfiChatResponse) throws {
            var rawResponse = rawResponse

            self.status = rawResponse.status
            self.message = String(cString: rawResponse.message)
            self.headers = Dictionary(uniqueKeysWithValues: rawResponse.rawHeadersAsBuffer.lazy.map { (rawHeader: UnsafePointer<CChar>?) -> (String, String) in
                guard let rawHeader else {
                    fatalError("null in headers list")
                }
                let asciiColon = Int32(Character(":").asciiValue!)
                guard let colonPtr = strchr(rawHeader, asciiColon) else {
                    fatalError("header returned without colon")
                }
                let nameCount = UnsafePointer(colonPtr) - rawHeader
                let name = UnsafeBufferPointer(start: rawHeader, count: nameCount).withMemoryRebound(to: UInt8.self) {
                    String(decoding: $0, as: UTF8.self)
                }
                let value = String(cString: colonPtr + 1)
                return (name, value)
            })

            // Avoid copying the body when possible!
            self.body = Data(bytesNoCopy: rawResponse.body.base, count: rawResponse.body.length, deallocator: .custom { base, length in
                signal_free_buffer(base, length)
            })
            // Clear it out so it doesn't get freed eagerly.
            rawResponse.body = .init()

            rawResponse.free()
        }
    }

    public struct DebugInfo: Equatable {
        public var reconnectCount: UInt32
        public var ipType: IpType
        public var duration: TimeInterval
        public var connectionInfo: String

        public init(reconnectCount: UInt32, ipType: IpType, duration: TimeInterval, connectionInfo: String) {
            self.reconnectCount = reconnectCount
            self.ipType = ipType
            self.duration = duration
            self.connectionInfo = connectionInfo
        }

        internal init(consuming rawDebugInfo: SignalFfiChatServiceDebugInfo) {
            var rawDebugInfo = rawDebugInfo
            defer { rawDebugInfo.free() }
            self.reconnectCount = rawDebugInfo.reconnect_count
            self.ipType = IpType(rawValue: rawDebugInfo.raw_ip_type) ?? .unknown
            self.duration = rawDebugInfo.duration_secs
            self.connectionInfo = String(cString: rawDebugInfo.connection_info)
        }
    }

    fileprivate let tokioAsyncContext: TokioAsyncContext

    internal init(tokioAsyncContext: TokioAsyncContext, connectionManager: ConnectionManager, username: String, password: String) {
        var handle: OpaquePointer?
        connectionManager.withNativeHandle { connectionManager in
            failOnError(signal_chat_service_new(&handle, connectionManager, username, password))
        }
        self.tokioAsyncContext = tokioAsyncContext
        super.init(owned: handle!)
    }

    internal required init(owned handle: OpaquePointer) {
        fatalError("should not be called directly for a ChatService")
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_chat_destroy(handle)
    }

    /// Sets (or clears) the listener for server push messages on the authenticated connection.
    ///
    /// Takes ownership of the listener; be careful this doesn't lead to a reference cycle (unless the owner lives forever anyway).
    public func setListener(_ listener: (any ChatListener)?) {
        self.tokioAsyncContext.withNativeHandle { tokioAsyncContext in
            withNativeHandle { chatService in
                if let listener {
                    var listenerStruct = ChatListenerBridge(chatService: self, chatListener: listener).makeListenerStruct()
                    failOnError(signal_chat_server_set_listener(tokioAsyncContext, chatService, &listenerStruct))
                } else {
                    failOnError(signal_chat_server_set_listener(tokioAsyncContext, chatService, nil))
                }
            }
        }
    }

    /// Initiates establishing of the underlying authenticated connection to the Chat Service. Once the
    /// service is connected, all the requests will be using the established connection. Also, if the
    /// connection is lost for any reason other than the call to ``disconnect()``, an automatic
    /// reconnect attempt will be made.
    ///
    /// Calling this method will result in starting to accept incoming requests from the Chat Service.
    /// You should set a listener first using ``setListener(_:)``.
    @discardableResult
    public func connectAuthenticated() async throws -> DebugInfo {
        let rawDebugInfo = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                signal_chat_service_connect_auth(promise, tokioAsyncContext, chatService)
            }
        }
        return DebugInfo(consuming: rawDebugInfo)
    }

    /// Initiates establishing of the underlying authenticated connection to the Chat Service. Once the
    /// service is connected, all the requests will be using the established connection. Also, if the
    /// connection is lost for any reason other than the call to ``disconnect()``, an automatic
    /// reconnect attempt will be made.
    @discardableResult
    public func connectUnauthenticated() async throws -> DebugInfo {
        let rawDebugInfo = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                signal_chat_service_connect_unauth(promise, tokioAsyncContext, chatService)
            }
        }
        return DebugInfo(consuming: rawDebugInfo)
    }

    /// Initiates termination of the underlying connection to the Chat Service. After the service is
    /// disconnected, it will not attempt to automatically reconnect until you call
    /// ``connectAuthenticated()`` and/or ``connectUnauthenticated()``.
    ///
    /// Note: the same instance of `ChatService` can be reused after `disconnect()` was
    /// called.
    ///
    /// Returns when the disconnection is complete.
    public func disconnect() async throws {
        _ = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatService in
                signal_chat_service_disconnect(promise, tokioAsyncContext, chatService)
            }
        }
    }

    /// Sends request to the Chat Service over an unauthenticated channel.
    ///
    /// - Throws: ``SignalError/chatServiceInactive(_:)`` if you haven't called ``connectUnauthenticated()``
    /// - SeeAlso: ``unauthenticatedSendAndDebug(_:)``
    public func unauthenticatedSend(_ request: Request) async throws -> Response {
        let internalRequest = try InternalRequest(request)
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
    /// - Throws: ``SignalError/chatServiceInactive(_:)`` if you haven't called ``connectUnauthenticated()``
    /// - SeeAlso: ``unauthenticatedSend(_:)``
    public func unauthenticatedSendAndDebug(_ request: Request) async throws -> (Response, DebugInfo) {
        let internalRequest = try InternalRequest(request)
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

    /// Sends request to the Chat Service over an authenticated channel.
    ///
    /// - Throws: ``SignalError/chatServiceInactive(_:)`` if you haven't called ``connectAuthenticated()``
    /// - SeeAlso: ``authenticatedSendAndDebug(_:)``
    public func authenticatedSend(_ request: Request) async throws -> Response {
        let internalRequest = try InternalRequest(request)
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
    /// - Throws: ``SignalError/chatServiceInactive(_:)`` if you haven't called ``connectAuthenticated()``
    /// - SeeAlso: ``authenticatedSend(_:)``
    public func authenticatedSendAndDebug(_ request: Request) async throws -> (Response, DebugInfo) {
        let internalRequest = try InternalRequest(request)
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

    // Exposed for testing
    internal class InternalRequest: NativeHandleOwner {
        convenience init(_ request: Request) throws {
            var handle: OpaquePointer?
            if let body = request.body {
                try body.withUnsafeBorrowedBuffer { body in
                    try checkError(signal_http_request_new_with_body(&handle, request.method, request.pathAndQuery, body))
                }
            } else {
                try checkError(signal_http_request_new_without_body(&handle, request.method, request.pathAndQuery))
            }
            // Make sure we clean up the handle if there are any errors adding headers.
            self.init(owned: handle!)

            for (name, value) in request.headers {
                try checkError(signal_http_request_add_header(handle, name, value))
            }
        }

        override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
            return signal_http_request_destroy(handle)
        }
    }
}

extension SignalFfiChatResponse {
    fileprivate var rawHeadersAsBuffer: UnsafeBufferPointer<UnsafePointer<CChar>?> {
        .init(start: self.headers.base, count: self.headers.length)
    }

    /// Assumes the response was created from Rust, and frees all the members.
    ///
    /// Do not use the response after this!
    internal mutating func free() {
        signal_free_string(message)
        signal_free_list_of_strings(headers)
        signal_free_buffer(body.base, body.length)
        // Zero out all the fields to be sure they won't be reused.
        self = .init()
    }
}

extension SignalFfiChatServiceDebugInfo {
    fileprivate mutating func free() {
        signal_free_string(connection_info)
        // Zero out all the fields to be sure they won't be reused.
        self = .init()
    }
}
