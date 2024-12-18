//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class SenderKeyMessage: NativeHandleOwner<SignalMutPointerSenderKeyMessage> {
    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerSenderKeyMessage>) -> SignalFfiErrorRef? {
        return signal_sender_key_message_destroy(handle.pointer)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        var result = SignalMutPointerSenderKeyMessage()
        try bytes.withUnsafeBorrowedBuffer {
            try checkError(signal_sender_key_message_deserialize(&result, $0))
        }
        self.init(owned: NonNull(result)!)
    }

    public var distributionId: UUID {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningUuid {
                    signal_sender_key_message_get_distribution_id($0, nativeHandle.const())
                }
            }
        }
    }

    public var chainId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_sender_key_message_get_chain_id($0, nativeHandle.const())
                }
            }
        }
    }

    public var iteration: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_sender_key_message_get_iteration($0, nativeHandle.const())
                }
            }
        }
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_sender_key_message_serialize($0, nativeHandle.const())
                }
            }
        }
    }

    public var ciphertext: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_sender_key_message_get_cipher_text($0, nativeHandle.const())
                }
            }
        }
    }

    public func verifySignature(against key: PublicKey) throws -> Bool {
        var result = false
        try withNativeHandles(self, key) { messageHandle, keyHandle in
            try checkError(signal_sender_key_message_verify_signature(&result, messageHandle.const(), keyHandle.const()))
        }
        return result
    }
}

extension SignalMutPointerSenderKeyMessage: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerSenderKeyMessage

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

extension SignalConstPointerSenderKeyMessage: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
