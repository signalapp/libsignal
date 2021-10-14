//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class PlaintextContent: NativeHandleOwner {
    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_plaintext_content_destroy(handle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        var result: OpaquePointer?
        try bytes.withUnsafeBytes {
            try checkError(signal_plaintext_content_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
        }
        self.init(owned: result!)
    }

    public convenience init(_ decryptionError: DecryptionErrorMessage) {
        var result: OpaquePointer?
        failOnError(signal_plaintext_content_from_decryption_error_message(&result, decryptionError.nativeHandle))
        self.init(owned: result!)
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

public class DecryptionErrorMessage: NativeHandleOwner {
    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_decryption_error_message_destroy(handle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        var result: OpaquePointer?
        try bytes.withUnsafeBytes {
            try checkError(signal_decryption_error_message_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
        }
        self.init(owned: result!)
    }

    public convenience init<Bytes: ContiguousBytes>(originalMessageBytes bytes: Bytes, type: CiphertextMessage.MessageType, timestamp: UInt64, originalSenderDeviceId: UInt32) throws {
        var result: OpaquePointer?
        try bytes.withUnsafeBytes {
            try checkError(signal_decryption_error_message_for_original_message(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count, type.rawValue, timestamp, originalSenderDeviceId))
        }
        self.init(owned: result!)
    }

    // For testing
    public static func extractFromSerializedContent<Bytes: ContiguousBytes>(_ bytes: Bytes) throws -> DecryptionErrorMessage {
        var result: OpaquePointer?
        try bytes.withUnsafeBytes {
            try checkError(signal_decryption_error_message_extract_from_serialized_content(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
        }
        return DecryptionErrorMessage(owned: result!)
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
            try invokeFnReturningOptionalNativeHandle {
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
