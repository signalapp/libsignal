//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class SignalMessage: NativeHandleOwner<SignalMutPointerSignalMessage> {
    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerSignalMessage>) -> SignalFfiErrorRef? {
        return signal_message_destroy(handle.pointer)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        var result = SignalMutPointerSignalMessage()
        try bytes.withUnsafeBorrowedBuffer {
            try checkError(signal_message_deserialize(&result, $0))
        }
        self.init(owned: NonNull(result)!)
    }

    public var senderRatchetKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_message_get_sender_ratchet_key($0, nativeHandle.const())
                }
            }
        }
    }

    public var body: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_message_get_body($0, nativeHandle.const())
                }
            }
        }
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_message_get_serialized($0, nativeHandle.const())
                }
            }
        }
    }

    public var messageVersion: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_message_get_message_version($0, nativeHandle.const())
                }
            }
        }
    }

    public var counter: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_message_get_counter($0, nativeHandle.const())
                }
            }
        }
    }

    public func verifyMac<Bytes: ContiguousBytes>(
        sender: PublicKey,
        receiver: PublicKey,
        macKey: Bytes
    ) throws -> Bool {
        return try withNativeHandles(self, sender, receiver) { messageHandle, senderHandle, receiverHandle in
            try macKey.withUnsafeBorrowedBuffer {
                var result = false
                try checkError(signal_message_verify_mac(
                    &result,
                    messageHandle.const(),
                    senderHandle.const(),
                    receiverHandle.const(),
                    $0
                ))
                return result
            }
        }
    }
}

extension SignalMutPointerSignalMessage: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerSignalMessage

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

extension SignalConstPointerSignalMessage: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
