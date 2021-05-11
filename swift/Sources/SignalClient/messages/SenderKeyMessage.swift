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

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        handle = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_sender_key_message_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
    }

    public var distributionId: UUID {
        return failOnError {
            try invokeFnReturningUuid {
                signal_sender_key_message_get_distribution_id($0, handle)
            }
        }
    }

    public var chainId: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_sender_key_message_get_chain_id($0, handle)
            }
        }
    }

    public var iteration: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_sender_key_message_get_iteration($0, handle)
            }
        }
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_sender_key_message_serialize($0, $1, handle)
            }
        }
    }

    public var ciphertext: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_sender_key_message_get_cipher_text($0, $1, handle)
            }
        }
    }

    public func verifySignature(against key: PublicKey) throws -> Bool {
        var result: Bool = false
        try checkError(signal_sender_key_message_verify_signature(&result, handle, key.nativeHandle))
        return result
    }
}
