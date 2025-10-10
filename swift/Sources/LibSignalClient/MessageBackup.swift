//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// Key used to encrypt and decrypt a message backup bundle.
///
/// - SeeAlso: ``BackupKey``
public class MessageBackupKey: NativeHandleOwner<SignalMutPointerMessageBackupKey>, @unchecked Sendable {
    /// Derives a `MessageBackupKey` from the given account entropy pool.
    ///
    /// `accountEntropy` must be a **validated** account entropy pool;
    /// passing an arbitrary String here is considered a programmer error.
    public convenience init(
        accountEntropy: String,
        aci: Aci,
        forwardSecrecyToken: BackupForwardSecrecyToken? = nil
    ) throws {
        let handle = try withAllBorrowed(aci, .fixed(forwardSecrecyToken)) {
            aci,
            forwardSecrecyToken in
            try invokeFnReturningValueByPointer(.init()) {
                signal_message_backup_key_from_account_entropy_pool(
                    $0,
                    accountEntropy,
                    aci,
                    forwardSecrecyToken
                )
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    /// Derives a `MessageBackupKey` from the given backup key and ID.
    ///
    /// Used when reading from a local backup, which may have been created with a different ACI.
    public convenience init(
        backupKey: BackupKey,
        backupId: Data,
        forwardSecrecyToken: BackupForwardSecrecyToken? = nil
    ) throws {
        let backupId = try ByteArray(newContents: backupId, expectedLength: 16)
        let handle = try withAllBorrowed(.fixed(backupKey), .fixed(backupId), .fixed(forwardSecrecyToken)) {
            backupKey,
            backupId,
            forwardSecrecyToken in
            try invokeFnReturningValueByPointer(.init()) {
                signal_message_backup_key_from_backup_key_and_backup_id(
                    $0,
                    backupKey,
                    backupId,
                    forwardSecrecyToken
                )
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    internal required init(owned handle: NonNull<SignalMutPointerMessageBackupKey>) {
        super.init(owned: handle)
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerMessageBackupKey>
    ) -> SignalFfiErrorRef? {
        signal_message_backup_key_destroy(handle.pointer)
    }

    /// An HMAC key used to sign a backup file.
    public var hmacKey: Data {
        failOnError {
            try withNativeHandle { keyHandle in
                try invokeFnReturningFixedLengthArray {
                    signal_message_backup_key_get_hmac_key($0, keyHandle.const())
                }
            }
        }
    }

    /// An AES-256-CBC key used to encrypt a backup file.
    public var aesKey: Data {
        failOnError {
            try withNativeHandle { keyHandle in
                try invokeFnReturningFixedLengthArray {
                    signal_message_backup_key_get_aes_key($0, keyHandle.const())
                }
            }
        }
    }
}

extension SignalMutPointerMessageBackupKey: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerMessageBackupKey

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerMessageBackupKey: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

public enum MessageBackupPurpose: UInt8, Sendable {
    // This needs to be kept in sync with the Rust version of the enum.
    case deviceTransfer = 0
    case remoteBackup = 1
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
    key: MessageBackupKey,
    purpose: MessageBackupPurpose,
    length: UInt64,
    makeStream: () throws -> SignalInputStream
) throws -> MessageBackupUnknownFields {
    let outcome: ValidationOutcome = try withInputStream(try makeStream()) { firstInput in
        try withInputStream(try makeStream()) { secondInput in
            try key.withNativeHandle { key in
                try invokeFnReturningNativeHandle {
                    signal_message_backup_validator_validate(
                        $0,
                        key.const(),
                        firstInput,
                        secondInput,
                        length,
                        purpose.rawValue
                    )
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
public class OnlineBackupValidator: NativeHandleOwner<SignalMutPointerOnlineBackupValidator> {
    /// Initializes an OnlineBackupValidator from the given BackupInfo protobuf message.
    ///
    /// "Soft" errors will be logged, including unrecognized fields in the protobuf.
    ///
    /// - Throws: ``MessageBackupValidationError`` on error.
    public convenience init<Bytes: ContiguousBytes>(backupInfo: Bytes, purpose: MessageBackupPurpose) throws {
        let handle = try backupInfo.withUnsafeBorrowedBuffer { backupInfo in
            try invokeFnReturningValueByPointer(.init()) {
                signal_online_backup_validator_new($0, backupInfo, purpose.rawValue)
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    internal required init(owned handle: NonNull<SignalMutPointerOnlineBackupValidator>) {
        super.init(owned: handle)
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerOnlineBackupValidator>
    ) -> SignalFfiErrorRef? {
        signal_online_backup_validator_destroy(handle.pointer)
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

extension SignalMutPointerOnlineBackupValidator: SignalMutPointer {
    public typealias ConstPointer = OpaquePointer?

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        nil
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

private class ValidationOutcome: NativeHandleOwner<SignalMutPointerMessageBackupValidationOutcome> {
    public var unknownFields: MessageBackupUnknownFields {
        let fields = failOnError {
            try self.withNativeHandle { result in
                try invokeFnReturningStringArray {
                    signal_message_backup_validation_outcome_get_unknown_fields($0, result.const())
                }
            }
        }
        return MessageBackupUnknownFields(fields: fields)
    }

    public var errorMessage: String? {
        try! self.withNativeHandle { result in
            try invokeFnReturningOptionalString {
                signal_message_backup_validation_outcome_get_error_message($0, result.const())
            }
        }
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerMessageBackupValidationOutcome>
    ) -> SignalFfiErrorRef? {
        signal_message_backup_validation_outcome_destroy(handle.pointer)
    }
}

extension SignalMutPointerMessageBackupValidationOutcome: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerMessageBackupValidationOutcome

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerMessageBackupValidationOutcome: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
