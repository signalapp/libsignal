//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class MessageBackupKey: NativeHandleOwner {
    public convenience init(masterKey: [UInt8], aci: Aci) throws {
        let masterKey = try ByteArray(newContents: masterKey, expectedLength: 32)
        let handle = try masterKey.withUnsafePointerToSerialized { masterKey in
            try aci.withPointerToFixedWidthBinary { aci in
                var outputHandle: OpaquePointer?
                try checkError(signal_message_backup_key_new(&outputHandle, masterKey, aci))
                return outputHandle
            }
        }
        self.init(owned: handle!)
    }

    internal required init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        signal_message_backup_key_destroy(handle)
    }
}

public enum MessageBackupPurpose: UInt8 {
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
///  - `SignalError.ioError`: If an IO error on the input occurs.
///  - `MessageBackupValidationError`: If validation fails
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

/// An in-memory representation of a backup file used to compare contents.
///
/// When comparing the contents of two backups:
///   1. Create a `ComparableBackup` instance for each of the inputs.
///   2. Check the `unknownFields()` value; if it's not empty, some parts of the
///      backup weren't parsed and won't be compared.
///   3. Produce a canonical string for each backup with `comparableString()`.
///   4. Compare the canonical string representations.
///
/// The diff of the canonical strings (which may be rather large) will show the
/// differences between the logical content of the input backup files.
public class ComparableBackup: NativeHandleOwner {
    /// Reads an unencrypted backup file into memory for comparison.
    ///
    /// - Parameters:
    ///  - purpose: Whether the backup is intended for transfer or remote storage.
    ///  - length: The exact length of the backup file, in bytes.
    ///  - stream: An InputStream that produces the backup contents.
    ///
    /// - Throws:
    ///  - `SignalError.ioError`: If an IO error on the input occurs.
    ///  - `SignalError.backupValidation`: If validation of the input fails.
    public convenience init(purpose: MessageBackupPurpose, length: UInt64, stream: SignalInputStream) throws {
        var handle: OpaquePointer?
        try checkError(
            try withInputStream(stream) { stream in
                signal_comparable_backup_read_unencrypted(&handle, stream, length, purpose.rawValue)
            }
        )
        self.init(owned: handle!)
    }

    /// Unrecognized protobuf fields present in the backup.
    ///
    /// If this is not empty, some parts of the backup were not recognized and
    /// won't be present in the string representation.
    public var unknownFields: MessageBackupUnknownFields {
        let fields = failOnError {
            try self.withNativeHandle { result in
                try invokeFnReturningStringArray {
                    signal_comparable_backup_get_unknown_fields($0, result)
                }
            }
        }
        return MessageBackupUnknownFields(fields: fields)
    }

    /// Produces a string representation of the contents.
    ///
    /// The returned strings for two backups will be equal if the backups
    /// contain the same logical content. If two backups' strings are not equal,
    /// the diff will show what is different between them.
    ///
    /// - Returns: a canonical string representation of the backup.
    public func comparableString() -> String {
        return failOnError {
            try self.withNativeHandle { result in
                try invokeFnReturningString {
                    signal_comparable_backup_get_comparable_string($0, result)
                }
            }
        }
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        signal_comparable_backup_destroy(handle)
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
public struct MessageBackupUnknownFields {
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
