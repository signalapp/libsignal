//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

// These APIs aren't available in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

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
    ///  - ``SignalError/ioError(_:)``: If an IO error on the input occurs.
    ///  - ``MessageBackupValidationError``: If validation of the input fails.
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

#else

// Stub out ComparableBackup for a better error message if it gets used in a device build.
// (Unfortunately there's no @available syntax for device vs simulator.)

/// An in-memory representation of a backup file used to compare contents.
@available(*, unavailable, message: "ComparableBackup is only available in the simulator.")
public class ComparableBackup {}

#endif
