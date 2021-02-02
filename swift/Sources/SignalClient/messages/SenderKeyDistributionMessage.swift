//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class SenderKeyDistributionMessage {
    private var handle: OpaquePointer?

    deinit {
        failOnError(signal_sender_key_distribution_message_destroy(handle))
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }

    public init(name: SenderKeyName, store: SenderKeyStore, context: StoreContext) throws {
        try context.withOpaquePointer { context in
            try withSenderKeyStore(store) {
                try checkError(signal_create_sender_key_distribution_message(&handle, name.nativeHandle,
                                                                             $0, context))
            }
        }
    }

    public init<Bytes: ContiguousBytes>(keyId: UInt32,
                                        iteration: UInt32,
                                        chainKey: Bytes,
                                        publicKey: PublicKey) throws {
        handle = try chainKey.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_sender_key_distribution_message_new(&result,
                                                                      keyId,
                                                                      iteration,
                                                                      $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                                      $0.count,
                                                                      publicKey.nativeHandle))
            return result
        }
    }

    public init(bytes: [UInt8]) throws {
        try checkError(signal_sender_key_distribution_message_deserialize(&handle, bytes, bytes.count))
    }

    public var signatureKey: PublicKey {
        return failOnError {
            try invokeFnReturningPublicKey {
                signal_sender_key_distribution_message_get_signature_key($0, handle)
            }
        }
    }

    public var id: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_sender_key_distribution_message_get_id($0, handle)
            }
        }
    }

    public var iteration: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_sender_key_distribution_message_get_iteration($0, handle)
            }
        }
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_sender_key_distribution_message_serialize($0, $1, handle)
            }
        }
    }

    public var chainKey: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_sender_key_distribution_message_get_chain_key($0, $1, handle)
            }
        }
    }
}
