//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// Supports operations on pins for Secure Value Recovery. This class provides hashing pins for
/// local verification and for use with the remote SVR service. In either case, all pins are UTF-8
/// encoded bytes that must be normalized *before* being provided to this class. Normalizing a
/// string pin requires the following steps:
///
///  1. The string should be trimmed for leading and trailing whitespace.
///  2. If the whole string consists of digits, then non-arabic digits must be replaced with their
///    arabic 0-9 equivalents.
///  3. The string must then be [NKFD normalized](https://unicode.org/reports/tr15/#Norm_Forms)

import Foundation
import SignalFfi

/// Create an encoded password hash string.
///
/// This creates a hashed pin that should be used for local pin verification only.
///
/// - parameter pin: A normalized, UTF-8 encoded byte representation of the pin
/// - returns: A hashed pin string that can be verified later
public func hashLocalPin<Bytes: ContiguousBytes>(_ pin: Bytes) throws -> String {
    try pin.withUnsafeBorrowedBuffer { buffer in
        try invokeFnReturningString {
            signal_pin_local_hash($0, buffer)
        }
    }
}

/// Verify an encoded password hash against a pin
///
/// - parameter pin: A normalized, UTF-8 encoded byte representation of the pin to verify
/// - parameter encodedHash: An encoded string of the hash, as returned by `localHash`
/// - returns: true if the pin matches the hash, false otherwise
///
public func verifyLocalPin<Bytes: ContiguousBytes>(_ pin: Bytes, againstEncodedHash encodedHash: String) throws -> Bool {
    try encodedHash.withCString { hashPtr in
        try pin.withUnsafeBorrowedBuffer { buffer in
            try invokeFnReturningBool {
                signal_pin_verify_local_hash($0, hashPtr, buffer)
            }
        }
    }
}

/// A hash of the pin that can be used to interact with a Secure Value Recovery service.
public class PinHash: NativeHandleOwner {
    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_pin_hash_destroy(handle)
    }

    /// A 32 byte secret that can be used to access a value in a secure store.
    public var accessKey: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningFixedLengthArray {
                    signal_pin_hash_access_key($0, nativeHandle)
                }
            }
        }
    }

    /// A 32 byte encryption key that can be used to encrypt or decrypt values before uploading them to a secure store.
    public var encryptionKey: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningFixedLengthArray {
                    signal_pin_hash_encryption_key($0, nativeHandle)
                }
            }
        }
    }

    /// Hash a pin for use with a remote SecureValueRecovery1 service.
    ///
    /// Note: This should be used with SVR1 only. For SVR1, the salt should be the backup id.
    /// For SVR2 clients, use ``PinHash/init(pin:username:mrenclave:)`` which handles salt construction.
    ///
    /// - parameter normalizedPin: A normalized, UTF-8 encoded byte representation of the pin to verify
    /// - parameter salt: A 32 byte salt
    /// - returns: A `PinHash`
    public convenience init<PinBytes: ContiguousBytes, SaltBytes: ContiguousBytes>(normalizedPin: PinBytes, salt: SaltBytes) throws {

        var result: OpaquePointer?
        try normalizedPin.withUnsafeBorrowedBuffer { pinBytes in
            try salt.withUnsafeBytes { saltBytes in
                try ByteArray(newContents: Array(saltBytes), expectedLength: 32).withUnsafePointerToSerialized { saltTuple in
                    try checkError(signal_pin_hash_from_salt(&result, pinBytes, saltTuple))
                }
            }
        }
        self.init(owned: result!)
    }

    /// Hash a pin for use with a remote SecureValueRecovery2 service.
    ///
    /// Note: This should be used with SVR2 only. For SVR1 clients, use ``PinHash/init(pin:salt:)``
    ///
    /// - parameter normalizedPin: An already normalized UTF-8 encoded byte representation of the pin
    /// - parameter username: The Basic Auth username used to authenticate with SVR2
    /// - parameter mrenclave: The mrenclave where the hashed pin will be stored
    /// - returns: A `PinHash`
    public convenience init<PinBytes: ContiguousBytes, MrenclaveBytes: ContiguousBytes>(normalizedPin: PinBytes, username: String, mrenclave: MrenclaveBytes) throws {
        var result: OpaquePointer?
        try normalizedPin.withUnsafeBorrowedBuffer { pinBytes in
            try mrenclave.withUnsafeBorrowedBuffer { mrenclaveBytes in
                try username.withCString { userBytes in
                    try checkError(signal_pin_hash_from_username_mrenclave(&result, pinBytes, userBytes, mrenclaveBytes))
                }
            }
        }
        self.init(owned: result!)
    }

}
