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
public class PinHash: NativeHandleOwner, @unchecked Sendable {
    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
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
    /// For SVR2 clients, use ``PinHash/init(normalizedPin:username:mrenclave:)`` which handles salt construction.
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
    /// Note: This should be used with SVR2 only. For SVR1 clients, use ``PinHash/init(normalizedPin:salt:)``
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

/// The randomly-generated user-memorized entropy used to derive the backup key, with other possible future uses.
public enum AccountEntropyPool {
    /// Generate a new entropy pool and return the canonical string representation.
    ///
    /// This pool contains log_2(36^64) = ~330 bits of cryptographic quality randomness.
    ///
    /// - returns: A 64 character string containing randomly chosen digits from [a-z0-9].
    public static func generate() -> String {
        return failOnError {
            try invokeFnReturningString {
                signal_account_entropy_pool_generate($0)
            }
        }
    }

    /// Derives an SVR key from the given account entropy pool.
    ///
    /// `accountEntropyPool` must be a **validated** account entropy pool;
    /// passing an arbitrary String here is considered a programmer error.
    public static func deriveSvrKey(_ accountEntropyPool: String) throws -> [UInt8] {
        try invokeFnReturningFixedLengthArray {
            signal_account_entropy_pool_derive_svr_key($0, accountEntropyPool)
        }
    }

    /// Derives a backup key from the given account entropy pool.
    ///
    /// `accountEntropyPool` must be a **validated** account entropy pool;
    /// passing an arbitrary String here is considered a programmer error.
    ///
    /// - SeeAlso: ``BackupKey/generateRandom()``
    public static func deriveBackupKey(_ accountEntropyPool: String) throws -> BackupKey {
        try invokeFnReturningSerialized {
            signal_account_entropy_pool_derive_backup_key($0, accountEntropyPool)
        }
    }
}

/// A key used for many aspects of backups.
///
/// Clients are typically concerned with two long-lived keys: a "messages" key (sometimes called
/// "the root backup key" or just "the backup key") that's derived from an ``AccountEntropyPool``,
/// and a "media" key (formally the "media root backup key") that's not derived from anything else.
public class BackupKey: ByteArray, @unchecked Sendable {
    public static let SIZE = 32

    /// Throws if `contents` is not ``SIZE`` (32) bytes.
    public required init(contents: [UInt8]) throws {
        try super.init(newContents: contents, expectedLength: Self.SIZE)
    }

    /// Generates a random backup key.
    ///
    /// Useful for tests and for the media root backup key, which is not derived from anything else.
    ///
    /// - SeeAlso: ``AccountEntropyPool/deriveBackupKey(_:)``
    public static func generateRandom() -> BackupKey {
        failOnError {
            var bytes: [UInt8] = Array(repeating: 0, count: Self.SIZE)
            try bytes.withUnsafeMutableBytes { try fillRandom($0) }
            return try BackupKey(contents: bytes)
        }
    }

    /// Derives the backup ID to use given the current device's ACI.
    ///
    /// Used for both messages and media backups.
    public func deriveBackupId(aci: Aci) -> [UInt8] {
        failOnError {
            try withUnsafePointerToSerialized { backupKey in
                try aci.withPointerToFixedWidthBinary { aci in
                    try invokeFnReturningFixedLengthArray {
                        signal_backup_key_derive_backup_id($0, backupKey, aci)
                    }
                }
            }
        }
    }

    /// Derives the backup EC key to use given the current device's ACI.
    ///
    /// Used for both messages and media backups.
    public func deriveEcKey(aci: Aci) -> PrivateKey {
        failOnError {
            try withUnsafePointerToSerialized { backupKey in
                try aci.withPointerToFixedWidthBinary { aci in
                    try invokeFnReturningNativeHandle {
                        signal_backup_key_derive_ec_key($0, backupKey, aci)
                    }
                }
            }
        }
    }

    /// Derives the AES key used for encrypted fields in local backup metadata.
    ///
    /// Only relevant for message backup keys.
    public func deriveLocalBackupMetadataKey() -> [UInt8] {
        failOnError {
            try withUnsafePointerToSerialized { backupKey in
                try invokeFnReturningFixedLengthArray {
                    signal_backup_key_derive_local_backup_metadata_key($0, backupKey)
                }
            }
        }
    }

    /// Derives the ID for uploading media with the name `mediaName`.
    ///
    /// Only relevant for media backup keys.
    public func deriveMediaId(_ mediaName: String) throws -> [UInt8] {
        try withUnsafePointerToSerialized { backupKey in
            try invokeFnReturningFixedLengthArray {
                signal_backup_key_derive_media_id($0, backupKey, mediaName)
            }
        }
    }

    /// Derives the composite encryption key for re-encrypting media with the given ID.
    ///
    /// This is a concatenation of an HMAC key (32 bytes) and an AES-CBC key (also 32 bytes).
    ///
    /// Only relevant for media backup keys.
    public func deriveMediaEncryptionKey(_ mediaId: [UInt8]) throws -> [UInt8] {
        let mediaId = try ByteArray(newContents: mediaId, expectedLength: 15)
        return try withUnsafePointerToSerialized { backupKey in
            try mediaId.withUnsafePointerToSerialized { mediaId in
                try invokeFnReturningFixedLengthArray {
                    signal_backup_key_derive_media_encryption_key($0, backupKey, mediaId)
                }
            }
        }
    }

    /// Derives the composite encryption key for uploading thumbnails with the given ID to the "transit tier" CDN.
    ///
    /// This is a concatenation of an HMAC key (32 bytes) and an AES-CBC key (also 32 bytes).
    ///
    /// Only relevant for media backup keys.
    public func deriveThumbnailTransitEncryptionKey(_ mediaId: [UInt8]) throws -> [UInt8] {
        let mediaId = try ByteArray(newContents: mediaId, expectedLength: 15)
        return try withUnsafePointerToSerialized { backupKey in
            try mediaId.withUnsafePointerToSerialized { mediaId in
                try invokeFnReturningFixedLengthArray {
                    signal_backup_key_derive_thumbnail_transit_encryption_key($0, backupKey, mediaId)
                }
            }
        }
    }
}
