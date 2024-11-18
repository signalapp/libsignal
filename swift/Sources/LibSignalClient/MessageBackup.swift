//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// Key used to encrypt and decrypt a message backup bundle.
///
/// - SeeAlso: ``BackupKey``
public class MessageBackupKey: NativeHandleOwner, @unchecked Sendable {
    @available(*, deprecated, message: "Use init(accountEntropy:aci:) instead")
    public convenience init(masterKey: [UInt8], aci: Aci) throws {
        let masterKey = try ByteArray(newContents: masterKey, expectedLength: 32)
        let handle = try masterKey.withUnsafePointerToSerialized { masterKey in
            try aci.withPointerToFixedWidthBinary { aci in
                var outputHandle: OpaquePointer?
                try checkError(signal_message_backup_key_from_master_key(&outputHandle, masterKey, aci))
                return outputHandle
            }
        }
        self.init(owned: handle!)
    }

    /// Derives a `MessageBackupKey` from the given account entropy pool.
    ///
    /// `accountEntropy` must be a **validated** account entropy pool;
    /// passing an arbitrary String here is considered a programmer error.
    public convenience init(accountEntropy: String, aci: Aci) throws {
        let handle = try aci.withPointerToFixedWidthBinary { aci in
            var outputHandle: OpaquePointer?
            try checkError(signal_message_backup_key_from_account_entropy_pool(&outputHandle, accountEntropy, aci))
            return outputHandle
        }
        self.init(owned: handle!)
    }

    /// Derives a `MessageBackupKey` from the given backup key and ID.
    ///
    /// Used when reading from a local backup, which may have been created with a different ACI.
    ///
    /// This uses AccountEntropyPool-based key derivation rules;
    /// it cannot be used to read a backup created from a master key.
    public convenience init(backupKey: BackupKey, backupId: [UInt8]) throws {
        let backupId = try ByteArray(newContents: backupId, expectedLength: 16)
        let handle = try backupKey.withUnsafePointerToSerialized { backupKey in
            try backupId.withUnsafePointerToSerialized { backupId in
                var outputHandle: OpaquePointer?
                try checkError(signal_message_backup_key_from_backup_key_and_backup_id(&outputHandle, backupKey, backupId))
                return outputHandle
            }
        }
        self.init(owned: handle!)
    }

    @available(*, deprecated, message: "Use the overload that takes a strongly-typed BackupKey instead")
    public convenience init(backupKey: [UInt8], backupId: [UInt8]) throws {
        let backupKey = try BackupKey(contents: backupKey)
        try self.init(backupKey: backupKey, backupId: backupId)
    }

    internal required init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        signal_message_backup_key_destroy(handle)
    }

    /// An HMAC key used to sign a backup file.
    public var hmacKey: [UInt8] {
        failOnError {
            try withNativeHandle { keyHandle in
                try invokeFnReturningFixedLengthArray {
                    signal_message_backup_key_get_hmac_key($0, keyHandle)
                }
            }
        }
    }

    /// An AES-256-CBC key used to encrypt a backup file.
    public var aesKey: [UInt8] {
        failOnError {
            try withNativeHandle { keyHandle in
                try invokeFnReturningFixedLengthArray {
                    signal_message_backup_key_get_aes_key($0, keyHandle)
                }
            }
        }
    }
}

public enum MessageBackupPurpose: UInt8, Sendable {
    // This needs to be kept in sync with the Rust version of the enum.
    case deviceTransfer = 0, remoteBackup = 1
}

/// Validates a message backup file.
///
/// - Parameters:
///  - key: The key used to decrypt the backup file.
///  - purpose: Whether the backup is intended for transfer or remote storage.
///  - length: The exact length of the backup file, in bytes.
///  - makeStream: A callback that produces InputStreams needed for backups.
///
/// - Returns: an object describing the validation outcome.
///
/// - Throws:
///  - ``SignalError/ioError(_:)``: If an IO error on the input occurs.
///  - ``MessageBackupValidationError``: If validation fails
///
/// - SeeAlso: ``OnlineBackupValidator``
public func validateMessageBackup(
    key: MessageBackupKey, purpose: MessageBackupPurpose, length: UInt64, makeStream: () throws -> SignalInputStream
) throws -> MessageBackupUnknownFields {
    let outcome: ValidationOutcome = try withInputStream(try makeStream()) { firstInput in
        try withInputStream(try makeStream()) { secondInput in
            try key.withNativeHandle { key in
                try invokeFnReturningNativeHandle {
                    signal_message_backup_validator_validate($0, key, firstInput, secondInput, length, purpose.rawValue)
                }
            }
        }
    }

    if let errorMessage = outcome.errorMessage {
        throw MessageBackupValidationError(errorMessage: errorMessage, unknownFields: outcome.unknownFields)
    }
    return outcome.unknownFields
}

/// An alternative to ``validateMessageBackup(key:purpose:length:makeStream:)`` that validates a backup frame-by-frame.
///
/// This is much faster than using `validateMessageBackup(...)` because it bypasses the decryption and decompression steps, but that also means it's validating less. Don't forget to call `finalize()`!
///
/// Unlike `validateMessageBackup(...)`, unknown fields are treated as "soft" errors and logged, rather than collected and returned to the app for processing.
///
/// # Example
///
/// ```
/// let validator = try OnlineBackupValidator(
///     backupInfo: backupInfoProto.serialize(),
///     purpose: .deviceTransfer)
/// repeat {
///   // ...generate Frames...
///   try validator.addFrame(frameProto.serialize())
/// }
/// try validator.finalize() // don't forget this!
/// ```
public class OnlineBackupValidator: NativeHandleOwner {
    /// Initializes an OnlineBackupValidator from the given BackupInfo protobuf message.
    ///
    /// "Soft" errors will be logged, including unrecognized fields in the protobuf.
    ///
    /// - Throws: ``MessageBackupValidationError`` on error.
    public convenience init<Bytes: ContiguousBytes>(backupInfo: Bytes, purpose: MessageBackupPurpose) throws {
        let handle = try backupInfo.withUnsafeBorrowedBuffer { backupInfo in
            var outputHandle: OpaquePointer?
            try checkError(signal_online_backup_validator_new(&outputHandle, backupInfo, purpose.rawValue))
            return outputHandle!
        }
        self.init(owned: handle)
    }

    internal required init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        signal_online_backup_validator_destroy(handle)
    }

    /// Processes a single Frame protobuf message.
    ///
    /// "Soft" errors will be logged, including unrecognized fields in the protobuf.
    ///
    /// - Throws: ``MessageBackupValidationError`` on error.
    public func addFrame<Bytes: ContiguousBytes>(_ frame: Bytes) throws {
        try withNativeHandle { handle in
            try frame.withUnsafeBorrowedBuffer { frame in
                try checkError(signal_online_backup_validator_add_frame(handle, frame))
            }
        }
    }

    /// Marks that a backup is complete, and does any final checks that require whole-file knowledge.
    ///
    /// "Soft" errors will be logged.
    ///
    /// - Throws: ``MessageBackupValidationError`` on error.
    public func finalize() throws {
        try withNativeHandle { handle in
            try checkError(signal_online_backup_validator_finalize(handle))
        }
    }
}

/// The outcome of a failed validation attempt.
public struct MessageBackupValidationError: Error {
    /// The human-readable error that caused validation to fail.
    public var errorMessage: String
    /// Unknown fields encountered while validating.
    public var unknownFields: MessageBackupUnknownFields
}

/// Unknown fields encountered while validating.
public struct MessageBackupUnknownFields: Sendable {
    public let fields: [String]
}

private class ValidationOutcome: NativeHandleOwner {
    public var unknownFields: MessageBackupUnknownFields {
        let fields = failOnError {
            try self.withNativeHandle { result in
                try invokeFnReturningStringArray {
                    signal_message_backup_validation_outcome_get_unknown_fields($0, result)
                }
            }
        }
        return MessageBackupUnknownFields(fields: fields)
    }

    public var errorMessage: String? {
        try! self.withNativeHandle { result in
            try invokeFnReturningOptionalString {
                signal_message_backup_validation_outcome_get_error_message($0, result)
            }
        }
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        signal_message_backup_validation_outcome_destroy(handle)
    }
}
