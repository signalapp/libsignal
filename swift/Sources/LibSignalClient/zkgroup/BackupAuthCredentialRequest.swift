//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class BackupAuthCredentialRequest: ByteArray {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: signal_backup_auth_credential_request_check_valid_contents)
    }

    public func issueCredential(timestamp: Date, backupLevel: BackupLevel, params: GenericServerSecretParams) -> BackupAuthCredentialResponse {
        return failOnError {
            self.issueCredential(timestamp: timestamp, backupLevel: backupLevel, params: params, randomness: try .generate())
        }
    }

    public func issueCredential(timestamp: Date, backupLevel: BackupLevel, params: GenericServerSecretParams, randomness: Randomness) -> BackupAuthCredentialResponse {
        return failOnError {
            try withUnsafeBorrowedBuffer { contents in
                try params.withUnsafeBorrowedBuffer { params in
                    try randomness.withUnsafePointerToBytes { randomness in
                        try invokeFnReturningVariableLengthSerialized {
                            signal_backup_auth_credential_request_issue_deterministic($0, contents, UInt64(timestamp.timeIntervalSince1970), backupLevel.rawValue, params, randomness)
                        }
                    }
                }
            }
        }
    }
}
