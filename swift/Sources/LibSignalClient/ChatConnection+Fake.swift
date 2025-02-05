//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

extension AuthenticatedChatConnection {
    internal class FakeChatRemote: NativeHandleOwner<SignalMutPointerFakeChatRemoteEnd> {
        private let tokioAsyncContext: TokioAsyncContext

        required init(owned: NonNull<SignalMutPointerFakeChatRemoteEnd>) {
            fatalError("must not be invoked directly")
        }

        init(handle: NonNull<SignalMutPointerFakeChatRemoteEnd>, tokioAsyncContext: TokioAsyncContext) {
            self.tokioAsyncContext = tokioAsyncContext
            super.init(owned: handle)
        }

        func injectServerRequest(base64: String) {
            self.injectServerRequest(Data(base64Encoded: base64)!)
        }

        func injectServerRequest(_ requestBytes: Data) {
            withNativeHandle { handle in
                requestBytes.withUnsafeBorrowedBuffer { requestBytes in
                    failOnError(signal_testing_fake_chat_remote_end_send_raw_server_request(handle.const(), requestBytes))
                }
            }
        }

        func getNextIncomingRequest() async throws -> (ChatRequest.InternalRequest, UInt64) {
            let request = try await self.tokioAsyncContext.invokeAsyncFunction { promise, asyncContext in
                withNativeHandle { handle in
                    signal_testing_fake_chat_remote_end_receive_incoming_request(promise, asyncContext.const(), handle.const())
                }
            }
            defer { signal_fake_chat_sent_request_destroy(request) }

            let httpRequest: ChatRequest.InternalRequest =
                try invokeFnReturningNativeHandle {
                    signal_testing_fake_chat_sent_request_take_http_request($0, request)
                }
            let requestId = try invokeFnReturningInteger { signal_testing_fake_chat_sent_request_request_id($0, request.const())
            }

            return (httpRequest, requestId)
        }

        func injectServerResponse(base64: String) {
            self.injectServerResponse(Data(base64Encoded: base64)!)
        }

        func injectServerResponse(_ responseBytes: Data) {
            withNativeHandle { handle in
                responseBytes.withUnsafeBorrowedBuffer { responseBytes in
                    failOnError(signal_testing_fake_chat_remote_end_send_raw_server_response(handle.const(), responseBytes))
                }
            }
        }

        func injectConnectionInterrupted() {
            withNativeHandle { handle in
                failOnError(signal_testing_fake_chat_remote_end_inject_connection_interrupted(handle.const()))
            }
        }

        override class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerFakeChatRemoteEnd>) -> SignalFfiErrorRef? {
            signal_fake_chat_remote_end_destroy(handle.pointer)
        }
    }

    private class FakeChatConnection: NativeHandleOwner<SignalMutPointerFakeChatConnection> {
        override class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerFakeChatConnection>) -> SignalFfiErrorRef? {
            signal_fake_chat_connection_destroy(handle.pointer)
        }
    }

    internal static func fakeConnect(tokioAsyncContext: TokioAsyncContext, listener: any ChatConnectionListener) -> (AuthenticatedChatConnection, FakeChatRemote) {
        let listenerBridge = ChatListenerBridge(chatConnectionListener: listener)
        var listenerStruct = listenerBridge
            .makeListenerStruct()

        var fakeChatConnection = SignalMutPointerFakeChatConnection()
        failOnError(
            withUnsafePointer(to: &listenerStruct) { listener in
                tokioAsyncContext.withNativeHandle { asyncContext in
                    signal_testing_fake_chat_connection_create(&fakeChatConnection, asyncContext.const(), SignalConstPointerFfiChatListenerStruct(raw: listener))
                }
            }
        )
        defer { signal_fake_chat_connection_destroy(fakeChatConnection) }

        return failOnError {
            var chatHandle = SignalMutPointerAuthenticatedChatConnection(untyped: nil)
            try checkError(signal_testing_fake_chat_connection_take_authenticated_chat(&chatHandle, fakeChatConnection.const()))
            let chat = AuthenticatedChatConnection(fakeHandle: NonNull(chatHandle)!, tokioAsyncContext: tokioAsyncContext)

            listenerBridge.setConnection(chatConnection: chat)
            var fakeRemoteHandle = SignalMutPointerFakeChatRemoteEnd()
            try checkError(signal_testing_fake_chat_connection_take_remote(&fakeRemoteHandle, fakeChatConnection.const()))

            let fakeRemote = FakeChatRemote(handle: NonNull(fakeRemoteHandle)!, tokioAsyncContext: tokioAsyncContext)
            return (chat, fakeRemote)
        }
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

extension SignalMutPointerFakeChatSentRequest: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerFakeChatSentRequest

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

extension SignalConstPointerFakeChatSentRequest: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

extension SignalCPromiseMutPointerFakeChatSentRequest: PromiseStruct {
    typealias Result = SignalMutPointerFakeChatSentRequest
}

#endif
