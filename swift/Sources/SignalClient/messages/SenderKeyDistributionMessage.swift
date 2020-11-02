//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class SenderKeyDistributionMessage {
    private var handle: OpaquePointer?

    deinit {
        signal_sender_key_distribution_message_destroy(handle)
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }

    public init(name: SenderKeyName, store: SenderKeyStore, context: UnsafeMutableRawPointer?) throws {
        try withSenderKeyStore(store) {
            try checkError(signal_create_sender_key_distribution_message(&handle, name.nativeHandle,
                                                                         $0, context))
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

    public func signatureKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey {
            signal_sender_key_distribution_message_get_signature_key($0, handle)
        }
    }

    public func id() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_sender_key_distribution_message_get_id(handle, $0)
        }
    }

    public func iteration() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_sender_key_distribution_message_get_iteration(handle, $0)
        }
    }

    public func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_sender_key_distribution_message_serialize(handle, $0, $1)
        }
    }

    public func chainKey() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_sender_key_distribution_message_get_chain_key(handle, $0, $1)
        }
    }
}
