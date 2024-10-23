//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class BackupAuthCredential: ByteArray, @unchecked Sendable {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: signal_backup_auth_credential_check_valid_contents)
    }

    public func present(serverParams: GenericServerPublicParams) -> BackupAuthCredentialPresentation {
        return failOnError {
            self.present(serverParams: serverParams, randomness: try .generate())
        }
    }

    public func present(serverParams: GenericServerPublicParams, randomness: Randomness) -> BackupAuthCredentialPresentation {
        return failOnError {
            try withUnsafeBorrowedBuffer { contents in
                try serverParams.withUnsafeBorrowedBuffer { serverParams in
                    try randomness.withUnsafePointerToBytes { randomness in
                        try invokeFnReturningVariableLengthSerialized {
                            signal_backup_auth_credential_present_deterministic($0, contents, serverParams, randomness)
                        }
                    }
                }
            }
        }
    }

    public var backupID: [UInt8] {
        return failOnError {
            try withUnsafeBorrowedBuffer { contents in
                try invokeFnReturningFixedLengthArray {
                    signal_backup_auth_credential_get_backup_id($0, contents)
                }
            }
        }
    }

    public var backupLevel: BackupLevel {
        return failOnError {
            let rawValue = try withUnsafeBorrowedBuffer { contents in
                try invokeFnReturningInteger {
                    signal_backup_auth_credential_get_backup_level($0, contents)
                }
            }
            guard let backupLevel = BackupLevel(rawValue: rawValue) else {
                throw SignalError.internalError("Invalid BackupLevel \(rawValue)")
            }
            return backupLevel
        }
    }

    public var type: BackupCredentialType {
        return failOnError {
            let rawValue = try withUnsafeBorrowedBuffer { contents in
                try invokeFnReturningInteger {
                    signal_backup_auth_credential_get_type($0, contents)
                }
            }
            guard let type = BackupCredentialType(rawValue: rawValue) else {
                throw SignalError.internalError("Invalid BackupCredentialType \(rawValue)")
            }
            return type
        }
    }
}
