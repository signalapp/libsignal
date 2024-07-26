//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class PlaintextContent: NativeHandleOwner {
    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_plaintext_content_destroy(handle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        var result: OpaquePointer?
        try bytes.withUnsafeBorrowedBuffer {
            try checkError(signal_plaintext_content_deserialize(&result, $0))
        }
        self.init(owned: result!)
    }

    public convenience init(_ decryptionError: DecryptionErrorMessage) {
        var result: OpaquePointer?
        decryptionError.withNativeHandle { decryptionErrorHandle in
            failOnError(signal_plaintext_content_from_decryption_error_message(&result, decryptionErrorHandle))
        }
        self.init(owned: result!)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_plaintext_content_serialize($0, nativeHandle)
                }
            }
        }
    }

    public var body: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_plaintext_content_get_body($0, nativeHandle)
                }
            }
        }
    }
}

public class DecryptionErrorMessage: NativeHandleOwner {
    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_decryption_error_message_destroy(handle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        var result: OpaquePointer?
        try bytes.withUnsafeBorrowedBuffer {
            try checkError(signal_decryption_error_message_deserialize(&result, $0))
        }
        self.init(owned: result!)
    }

    public convenience init<Bytes: ContiguousBytes>(originalMessageBytes bytes: Bytes, type: CiphertextMessage.MessageType, timestamp: UInt64, originalSenderDeviceId: UInt32) throws {
        var result: OpaquePointer?
        try bytes.withUnsafeBorrowedBuffer {
            try checkError(signal_decryption_error_message_for_original_message(&result, $0, type.rawValue, timestamp, originalSenderDeviceId))
        }
        self.init(owned: result!)
    }

    // For testing
    public static func extractFromSerializedContent<Bytes: ContiguousBytes>(_ bytes: Bytes) throws -> DecryptionErrorMessage {
        return try bytes.withUnsafeBorrowedBuffer { buffer in
            try invokeFnReturningNativeHandle {
                signal_decryption_error_message_extract_from_serialized_content($0, buffer)
            }
        }
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_decryption_error_message_serialize($0, nativeHandle)
                }
            }
        }
    }

    public var ratchetKey: PublicKey? {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningOptionalNativeHandle {
                    signal_decryption_error_message_get_ratchet_key($0, nativeHandle)
                }
            }
        }
    }

    public var timestamp: UInt64 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_decryption_error_message_get_timestamp($0, nativeHandle)
                }
            }
        }
    }

    public var deviceId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_decryption_error_message_get_device_id($0, nativeHandle)
                }
            }
        }
    }
}
