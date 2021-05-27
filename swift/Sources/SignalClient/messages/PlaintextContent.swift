//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class PlaintextContent {
    internal private(set) var nativeHandle: OpaquePointer

    deinit {
        failOnError(signal_plaintext_content_destroy(nativeHandle))
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        nativeHandle = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_plaintext_content_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }!
    }

    public init(_ decryptionError: DecryptionErrorMessage) {
        var result: OpaquePointer?
        failOnError(signal_plaintext_content_from_decryption_error_message(&result, decryptionError.nativeHandle))
        nativeHandle = result!
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_plaintext_content_serialize($0, $1, nativeHandle)
            }
        }
    }

    public var body: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_plaintext_content_get_body($0, $1, nativeHandle)
            }
        }
    }
}

public class DecryptionErrorMessage {
    fileprivate private(set) var nativeHandle: OpaquePointer

    deinit {
        failOnError(signal_decryption_error_message_destroy(nativeHandle))
    }

    fileprivate init(owned rawPtr: OpaquePointer) {
        nativeHandle = rawPtr
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        nativeHandle = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_decryption_error_message_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }!
    }

    public init<Bytes: ContiguousBytes>(originalMessageBytes bytes: Bytes, type: CiphertextMessage.MessageType, timestamp: UInt64, originalSenderDeviceId: UInt32) throws {
        nativeHandle = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_decryption_error_message_for_original_message(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count, type.rawValue, timestamp, originalSenderDeviceId))
            return result
        }!
    }

    // For testing
    public static func extractFromSerializedContent<Bytes: ContiguousBytes>(_ bytes: Bytes) throws -> DecryptionErrorMessage {
        try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_decryption_error_message_extract_from_serialized_content(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return DecryptionErrorMessage(owned: result!)
        }!
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_decryption_error_message_serialize($0, $1, nativeHandle)
            }
        }
    }

    public var ratchetKey: PublicKey? {
        return failOnError {
            try invokeFnReturningOptionalPublicKey {
                signal_decryption_error_message_get_ratchet_key($0, nativeHandle)
            }
        }
    }

    public var timestamp: UInt64 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_decryption_error_message_get_timestamp($0, nativeHandle)
            }
        }
    }

    public var deviceId: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_decryption_error_message_get_device_id($0, nativeHandle)
            }
        }
    }
}
