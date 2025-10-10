//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class SenderKeyMessage: NativeHandleOwner<SignalMutPointerSenderKeyMessage> {
    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerSenderKeyMessage>
    ) -> SignalFfiErrorRef? {
        return signal_sender_key_message_destroy(handle.pointer)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let result = try bytes.withUnsafeBorrowedBuffer { bytes in
            try invokeFnReturningValueByPointer(.init()) {
                signal_sender_key_message_deserialize($0, bytes)
            }
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

    public func serialize() -> Data {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_sender_key_message_serialize($0, nativeHandle.const())
                }
            }
        }
    }

    public var ciphertext: Data {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_sender_key_message_get_cipher_text($0, nativeHandle.const())
                }
            }
        }
    }

    public func verifySignature(against key: PublicKey) throws -> Bool {
        return try withAllBorrowed(self, key) { messageHandle, keyHandle in
            try invokeFnReturningBool {
                signal_sender_key_message_verify_signature($0, messageHandle.const(), keyHandle.const())
            }
        }
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
