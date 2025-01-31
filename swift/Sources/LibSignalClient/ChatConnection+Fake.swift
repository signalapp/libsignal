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
            let fakeRemote: FakeChatRemote = try invokeFnReturningNativeHandle {
                signal_testing_fake_chat_connection_take_remote($0, fakeChatConnection.const())
            }
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
#endif
