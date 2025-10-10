//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

extension AuthenticatedChatConnection {
    internal static func fakeConnect(
        tokioAsyncContext: TokioAsyncContext,
        listener: any ChatConnectionListener,
        alerts: [String] = []
    ) -> (AuthenticatedChatConnection, FakeChatRemote) {
        let (fakeChatConnection, listenerBridge) = failOnError {
            try FakeChatConnection.create(
                tokioAsyncContext: tokioAsyncContext,
                listener: listener,
                alerts: alerts
            )
        }

        return failOnError {
            let chatHandle = try fakeChatConnection.withNativeHandle { connectionHandle in
                try invokeFnReturningValueByPointer(.init()) {
                    signal_testing_fake_chat_connection_take_authenticated_chat(
                        $0,
                        connectionHandle.const()
                    )
                }
            }
            let chat = AuthenticatedChatConnection(
                fakeHandle: NonNull(chatHandle)!,
                tokioAsyncContext: tokioAsyncContext
            )

            listenerBridge.setConnection(chatConnection: chat)
            let fakeRemoteHandle = try fakeChatConnection.withNativeHandle { connectionHandle in
                try invokeFnReturningValueByPointer(.init()) {
                    signal_testing_fake_chat_connection_take_remote(
                        $0,
                        connectionHandle.const()
                    )
                }
            }

            let fakeRemote = FakeChatRemote(
                handle: NonNull(fakeRemoteHandle)!,
                tokioAsyncContext: tokioAsyncContext
            )
            return (chat, fakeRemote)
        }
    }
}

extension UnauthenticatedChatConnection {
    internal static func fakeConnect(
        tokioAsyncContext: TokioAsyncContext,
        listener: any ConnectionEventsListener<UnauthenticatedChatConnection>
    ) -> (UnauthenticatedChatConnection, FakeChatRemote) {
        let (fakeChatConnection, listenerBridge) = failOnError {
            try FakeChatConnection.create(
                tokioAsyncContext: tokioAsyncContext,
                listener: listener,
                alerts: []
            )
        }

        return failOnError {
            let chatHandle = try fakeChatConnection.withNativeHandle { connectionHandle in
                try invokeFnReturningValueByPointer(.init()) {
                    signal_testing_fake_chat_connection_take_authenticated_chat(
                        $0,
                        connectionHandle.const()
                    )
                }
            }
            let chat = UnauthenticatedChatConnection(
                fakeHandle: NonNull(chatHandle)!,
                tokioAsyncContext: tokioAsyncContext,
                environment: .staging
            )

            listenerBridge.setConnection(chatConnection: chat)
            let fakeRemoteHandle = try fakeChatConnection.withNativeHandle { connectionHandle in
                try invokeFnReturningValueByPointer(.init()) {
                    signal_testing_fake_chat_connection_take_remote(
                        $0,
                        connectionHandle.const()
                    )
                }
            }

            let fakeRemote = FakeChatRemote(
                handle: NonNull(fakeRemoteHandle)!,
                tokioAsyncContext: tokioAsyncContext
            )
            return (chat, fakeRemote)
        }
    }
}

private class SetChatLaterListenerBridge: ChatListenerBridge {
    private var savedAlerts: [String]?

    override init(chatConnectionListenerForTesting chatListener: any ChatConnectionListener) {
        super.init(chatConnectionListenerForTesting: chatListener)
    }

    func setConnection(chatConnection: AuthenticatedChatConnection) {
        self.chatConnection = chatConnection

        if let savedAlerts {
            super.didReceiveAlerts(savedAlerts)
            self.savedAlerts = nil
        }
    }

    // Override point for ChatConnection+Fake.
    override func didReceiveAlerts(_ alerts: [String]) {
        // This callback can happen before setConnection, so we might need to replay it later.
        guard self.chatConnection != nil else {
            self.savedAlerts = alerts
            return
        }

        super.didReceiveAlerts(alerts)
    }
}

private class SetChatLaterUnauthListenerBridge: UnauthConnectionEventsListenerBridge {
    override init(
        chatConnectionEventsListenerForTesting chatListener: any ConnectionEventsListener<UnauthenticatedChatConnection>
    ) {
        super.init(chatConnectionEventsListenerForTesting: chatListener)
    }

    func setConnection(chatConnection: UnauthenticatedChatConnection) {
        self.chatConnection = chatConnection
    }
}

internal class FakeChatRemote: NativeHandleOwner<SignalMutPointerFakeChatRemoteEnd> {
    private let tokioAsyncContext: TokioAsyncContext

    required init(owned: NonNull<SignalMutPointerFakeChatRemoteEnd>) {
        fatalError("must not be invoked directly")
    }

    init(
        handle: NonNull<SignalMutPointerFakeChatRemoteEnd>,
        tokioAsyncContext: TokioAsyncContext
    ) {
        self.tokioAsyncContext = tokioAsyncContext
        super.init(owned: handle)
    }

    func injectServerRequest(base64: String) {
        self.injectServerRequest(Data(base64Encoded: base64)!)
    }

    func injectServerRequest(_ requestBytes: Data) {
        withNativeHandle { handle in
            requestBytes.withUnsafeBorrowedBuffer { requestBytes in
                failOnError(
                    signal_testing_fake_chat_remote_end_send_raw_server_request(
                        handle.const(),
                        requestBytes
                    )
                )
            }
        }
    }

    func getNextIncomingRequest() async throws -> (ChatRequest.InternalRequest, UInt64) {
        while true {
            let request = try await self.tokioAsyncContext.invokeAsyncFunction { promise, asyncContext in
                withNativeHandle { handle in
                    signal_testing_fake_chat_remote_end_receive_incoming_request(
                        promise,
                        asyncContext.const(),
                        handle.const()
                    )
                }
            }
            guard request.present else {
                continue
            }

            let httpRequest = ChatRequest.InternalRequest(owned: NonNull(request.first)!)
            let requestId = request.second

            return (httpRequest, requestId)
        }
    }

    func sendResponse(requestId: UInt64, _ response: ChatResponse) throws {
        let fakeResponse = FakeChatResponse(requestId: requestId, response)
        try self.withNativeHandle { nativeHandle in
            try fakeResponse.withNativeHandle { response in
                try checkError(
                    signal_testing_fake_chat_remote_end_send_server_response(nativeHandle.const(), response.const())
                )
            }
        }
    }

    func injectServerResponse(base64: String) {
        self.injectServerResponse(Data(base64Encoded: base64)!)
    }

    func injectServerResponse(_ responseBytes: Data) {
        withNativeHandle { handle in
            responseBytes.withUnsafeBorrowedBuffer { responseBytes in
                failOnError(
                    signal_testing_fake_chat_remote_end_send_raw_server_response(
                        handle.const(),
                        responseBytes
                    )
                )
            }
        }
    }

    func injectConnectionInterrupted() {
        withNativeHandle { handle in
            failOnError(
                signal_testing_fake_chat_remote_end_inject_connection_interrupted(
                    handle.const()
                )
            )
        }
    }

    override class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerFakeChatRemoteEnd>
    ) -> SignalFfiErrorRef? {
        signal_fake_chat_remote_end_destroy(handle.pointer)
    }
}

internal class FakeChatServer: NativeHandleOwner<SignalMutPointerFakeChatServer>, @unchecked Sendable {
    internal let asyncContext: TokioAsyncContext
    internal init(asyncContext: TokioAsyncContext) {
        self.asyncContext = asyncContext

        let pointer = failOnError {
            try invokeFnReturningValueByPointer(.init()) {
                signal_testing_fake_chat_server_create($0)
            }
        }
        super.init(owned: NonNull(pointer)!)
    }

    internal required init(owned: NonNull<SignalMutPointerFakeChatServer>) {
        fatalError("cannot be invoked directly")
    }

    override class func destroyNativeHandle(
        _ nativeHandle: NonNull<SignalMutPointerFakeChatServer>
    ) -> SignalFfiErrorRef? {
        signal_fake_chat_server_destroy(nativeHandle.pointer)
    }

    internal func getNextRemote() async throws -> FakeChatRemote {
        let remote = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            self.withNativeHandle { nativeHandle in
                signal_testing_fake_chat_server_get_next_remote(promise, asyncContext.const(), nativeHandle.const())
            }
        }
        return FakeChatRemote(handle: NonNull(remote)!, tokioAsyncContext: self.asyncContext)
    }
}

internal class FakeChatResponse: NativeHandleOwner<SignalMutPointerFakeChatResponse> {
    internal init(requestId: UInt64, _ response: ChatResponse) {
        let nativeHandle = failOnError {
            try response.message.withCString { message in
                try response.headers.map { (key: String, value: String) in
                    "\(key): \(value)"
                }.withUnsafeBorrowedBytestringArray { headers in
                    try response.body.withUnsafeBorrowedBuffer { body in
                        try invokeFnReturningValueByPointer(.init()) {
                            signal_testing_fake_chat_response_create(
                                $0,
                                requestId,
                                response.status,
                                message,
                                headers,
                                SignalOptionalBorrowedSliceOfc_uchar(present: true, value: body)
                            )
                        }
                    }
                }
            }
        }
        super.init(owned: NonNull(nativeHandle)!)
    }

    internal required init(owned: NonNull<SignalMutPointerFakeChatResponse>) {
        fatalError("cannot be invoked directly")
    }

    override class func destroyNativeHandle(
        _ nativeHandle: NonNull<SignalMutPointerFakeChatResponse>
    ) -> SignalFfiErrorRef? {
        signal_fake_chat_response_destroy(nativeHandle.pointer)
    }
}

private class FakeChatConnection: NativeHandleOwner<SignalMutPointerFakeChatConnection> {
    static func create(
        tokioAsyncContext: TokioAsyncContext,
        listener: any ChatConnectionListener,
        alerts: [String]
    ) throws -> (FakeChatConnection, SetChatLaterListenerBridge) {
        let listenerBridge = SetChatLaterListenerBridge(
            chatConnectionListenerForTesting: listener
        )
        var listenerStruct = listenerBridge.makeListenerStruct()
        let chat = try FakeChatConnection.internalCreate(tokioAsyncContext, &listenerStruct, alerts)
        return (chat, listenerBridge)
    }

    static func create(
        tokioAsyncContext: TokioAsyncContext,
        listener: any ConnectionEventsListener<UnauthenticatedChatConnection>,
        alerts: [String]
    ) throws -> (FakeChatConnection, SetChatLaterUnauthListenerBridge) {
        let listenerBridge = SetChatLaterUnauthListenerBridge(
            chatConnectionEventsListenerForTesting: listener
        )
        var listenerStruct = listenerBridge.makeListenerStruct()
        let chat = try FakeChatConnection.internalCreate(tokioAsyncContext, &listenerStruct, alerts)
        return (chat, listenerBridge)
    }

    private static func internalCreate(
        _ tokioAsyncContext: TokioAsyncContext,
        _ listenerStruct: inout SignalFfiChatListenerStruct,
        _ alerts: [String]
    ) throws -> FakeChatConnection {
        let connection: FakeChatConnection = try withUnsafePointer(to: &listenerStruct) { listener in
            try tokioAsyncContext.withNativeHandle { asyncContext in
                try invokeFnReturningNativeHandle {
                    signal_testing_fake_chat_connection_create(
                        $0,
                        asyncContext.const(),
                        SignalConstPointerFfiChatListenerStruct(raw: listener),
                        alerts.joined(separator: "\n")
                    )
                }
            }
        }
        return connection
    }

    override class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerFakeChatConnection>
    ) -> SignalFfiErrorRef? {
        signal_fake_chat_connection_destroy(handle.pointer)
    }
}

extension SignalMutPointerFakeChatConnection: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerFakeChatConnection

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerFakeChatConnection: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

extension SignalMutPointerFakeChatRemoteEnd: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerFakeChatRemoteEnd

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerFakeChatRemoteEnd: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

extension SignalMutPointerFakeChatServer: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerFakeChatServer

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerFakeChatServer: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

extension SignalMutPointerFakeChatResponse: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerFakeChatResponse

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerFakeChatResponse: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

extension SignalCPromiseOptionalPairOfMutPointerHttpRequestu64: PromiseStruct {
    typealias Result = SignalOptionalPairOfMutPointerHttpRequestu64
}

extension SignalCPromiseMutPointerFakeChatRemoteEnd: PromiseStruct {
    typealias Result = SignalMutPointerFakeChatRemoteEnd
}

#endif
