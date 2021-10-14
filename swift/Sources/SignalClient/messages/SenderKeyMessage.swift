//
// Copyright 2020-2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class SenderKeyMessage: NativeHandleOwner {
    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_sender_key_message_destroy(handle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        var result: OpaquePointer?
        try bytes.withUnsafeBytes {
            try checkError(signal_sender_key_message_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
        }
        self.init(owned: result!)
    }

    public var distributionId: UUID {
        return failOnError {
            try invokeFnReturningUuid {
                signal_sender_key_message_get_distribution_id($0, nativeHandle)
            }
        }
    }

    public var chainId: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_sender_key_message_get_chain_id($0, nativeHandle)
            }
        }
    }

    public var iteration: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_sender_key_message_get_iteration($0, nativeHandle)
            }
        }
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_sender_key_message_serialize($0, $1, nativeHandle)
            }
        }
    }

    public var ciphertext: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_sender_key_message_get_cipher_text($0, $1, nativeHandle)
            }
        }
    }

    public func verifySignature(against key: PublicKey) throws -> Bool {
        var result: Bool = false
        try checkError(signal_sender_key_message_verify_signature(&result, nativeHandle, key.nativeHandle))
        return result
    }
}
