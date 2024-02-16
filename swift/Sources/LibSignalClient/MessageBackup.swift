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

  internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
    signal_message_backup_key_destroy(handle)
  }

}

/// Validates a message backup file.
///
/// - Parameters:
///  - key: The key used to decrypt the backup file.
///  - length: The exact length of the backup file, in bytes.
///  - makeStream: A callback that produces InputStreams needed for backups.
///
/// - Returns: an object describing the validation outcome.
///
/// - Throws:
///  - `SignalError.ioError`: If an IO error on the input occurs.
///  - `MessageBackupValidationError`: If validation fails
public func validateMessageBackup(
  key: MessageBackupKey, length: UInt64, makeStream: () -> SignalInputStream
) throws -> MessageBackupUnknownFields {
  let outcome: ValidationOutcome = try withInputStream(makeStream()) { firstInput in
    try withInputStream(makeStream()) { secondInput in
      try key.withNativeHandle { key in
        try invokeFnReturningNativeHandle {
          signal_message_backup_validator_validate($0, key, firstInput, secondInput, length)
        }
      }
    }
  }

  if let errorMessage = outcome.errorMessage {
    throw MessageBackupValidationError(errorMessage: errorMessage, unknownFields: outcome.unknownFields)
  }
  return outcome.unknownFields
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

  internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
    signal_message_backup_validation_outcome_destroy(handle)
  }
}
