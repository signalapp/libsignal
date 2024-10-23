//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class BackupAuthCredentialRequestContext: ByteArray, @unchecked Sendable {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: signal_backup_auth_credential_request_context_check_valid_contents)
    }

    public static func create<BackupKey: ContiguousBytes>(backupKey: BackupKey, aci: UUID) -> Self {
        return failOnError {
            try backupKey.withUnsafeBytes { backupKeyBytes in
                try ByteArray(newContents: Array(backupKeyBytes), expectedLength: 32).withUnsafePointerToSerialized { backupKeyTuple in
                    try withUnsafePointer(to: aci.uuid) { uuid in
                        try invokeFnReturningVariableLengthSerialized {
                            signal_backup_auth_credential_request_context_new($0, backupKeyTuple, uuid)
                        }
                    }
                }
            }
        }
    }

    public func getRequest() -> BackupAuthCredentialRequest {
        return failOnError {
            try withUnsafeBorrowedBuffer { contents in
                try invokeFnReturningVariableLengthSerialized {
                    signal_backup_auth_credential_request_context_get_request($0, contents)
                }
            }
        }
    }

    public func receive(_ response: BackupAuthCredentialResponse, timestamp: Date, params: GenericServerPublicParams) throws -> BackupAuthCredential {
        return try withUnsafeBorrowedBuffer { contents in
            try response.withUnsafeBorrowedBuffer { response in
                try params.withUnsafeBorrowedBuffer { params in
                    try invokeFnReturningVariableLengthSerialized {
                        signal_backup_auth_credential_request_context_receive_response($0, contents, response, UInt64(timestamp.timeIntervalSince1970), params)
                    }
                }
            }
        }
    }
}
