//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class SenderKeyMessage {
    private var handle: OpaquePointer?

    deinit {
        failOnError(signal_sender_key_message_destroy(handle))
    }

    public init<Bytes: ContiguousBytes>(keyId: UInt32,
                                        iteration: UInt32,
                                        ciphertext: Bytes,
                                        privateKey: PrivateKey) throws {
        handle = try ciphertext.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_sender_key_message_new(&result,
                                                         keyId,
                                                         iteration,
                                                         $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                         $0.count,
                                                         privateKey.nativeHandle))
            return result
        }
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        handle = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_sender_key_message_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
    }

    public var keyId: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_sender_key_message_get_key_id(handle, $0)
            }
        }
    }

    public var iteration: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_sender_key_message_get_iteration(handle, $0)
            }
        }
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_sender_key_message_serialize(handle, $0, $1)
            }
        }
    }

    public var ciphertext: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_sender_key_message_get_cipher_text(handle, $0, $1)
            }
        }
    }

    public func verifySignature(against key: PublicKey) throws -> Bool {
        var result: Bool = false
        try checkError(signal_sender_key_message_verify_signature(&result, handle, key.nativeHandle))
        return result
    }
}
