//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class SignalMessage {
    private var handle: OpaquePointer?

    deinit {
        failOnError(signal_message_destroy(handle))
    }

    internal init(owned rawPtr: OpaquePointer?) {
        handle = rawPtr
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        handle = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_message_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
    }

    public init<MacBytes, CiphertextBytes>(version: UInt8,
                                           macKey: MacBytes,
                                           senderRatchetKey: PublicKey,
                                           counter: UInt32,
                                           previousCounter: UInt32,
                                           ciphertext: CiphertextBytes,
                                           sender senderIdentityKey: PublicKey,
                                           receiver receiverIdentityKey: PublicKey) throws
    where MacBytes: ContiguousBytes, CiphertextBytes: ContiguousBytes {
        handle = try macKey.withUnsafeBytes { macBytes in
            try ciphertext.withUnsafeBytes { ciphertextBytes in
                var result: OpaquePointer?
                try checkError(signal_message_new(&result,
                                                  version,
                                                  macBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                  macBytes.count,
                                                  senderRatchetKey.nativeHandle,
                                                  counter,
                                                  previousCounter,
                                                  ciphertextBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                  ciphertextBytes.count,
                                                  senderIdentityKey.nativeHandle,
                                                  receiverIdentityKey.nativeHandle))
                return result
            }
        }
    }

    public var senderRatchetKey: PublicKey {
        return failOnError {
            try invokeFnReturningPublicKey {
                signal_message_get_sender_ratchet_key($0, handle)
            }
        }
    }

    public var body: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_message_get_body(handle, $0, $1)
            }
        }
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_message_get_serialized(handle, $0, $1)
            }
        }
    }

    public var messageVersion: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_message_get_message_version(handle, $0)
            }
        }
    }

    public var counter: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_message_get_counter(handle, $0)
            }
        }
    }

    public func verifyMac<Bytes: ContiguousBytes>(sender: PublicKey,
                                                  receiver: PublicKey,
                                                  macKey: Bytes) throws -> Bool {
        return try macKey.withUnsafeBytes {
            var result: Bool = false
            try checkError(signal_message_verify_mac(&result,
                                                     handle,
                                                     sender.nativeHandle,
                                                     receiver.nativeHandle,
                                                     $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                     $0.count))
            return result
        }
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }

}
