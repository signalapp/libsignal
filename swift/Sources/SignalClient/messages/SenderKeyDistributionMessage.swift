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

    public init(from sender: ProtocolAddress,
                distributionId: UUID,
                store: SenderKeyStore,
                context: StoreContext) throws {
        try context.withOpaquePointer { context in
            try withUnsafePointer(to: distributionId.uuid) { distributionId in
                try withSenderKeyStore(store) {
                    try checkError(signal_sender_key_distribution_message_create(&handle,
                                                                                 sender.nativeHandle,
                                                                                 distributionId,
                                                                                 $0, context))
                }
            }
        }
    }

    public init<Bytes: ContiguousBytes>(distributionId: UUID,
                                        chainId: UInt32,
                                        iteration: UInt32,
                                        chainKey: Bytes,
                                        publicKey: PublicKey) throws {
        var result: OpaquePointer?
        try chainKey.withUnsafeBytes { chainKeyBytes in
            try withUnsafePointer(to: distributionId.uuid) { distributionId in
                try checkError(signal_sender_key_distribution_message_new(&result,
                                                                          distributionId,
                                                                          chainId,
                                                                          iteration,
                                                                          chainKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                                          chainKeyBytes.count,
                                                                          publicKey.nativeHandle))
            }
        }
        handle = result
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
                signal_sender_key_distribution_message_get_chain_id($0, handle)
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
