//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class CreateCallLinkCredentialRequest: ByteArray, @unchecked Sendable {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: signal_create_call_link_credential_request_check_valid_contents)
    }

    public func issueCredential(userId: Aci, timestamp: Date, params: GenericServerSecretParams) -> CreateCallLinkCredentialResponse {
        return failOnError {
            self.issueCredential(userId: userId, timestamp: timestamp, params: params, randomness: try .generate())
        }
    }

    public func issueCredential(userId: Aci, timestamp: Date, params: GenericServerSecretParams, randomness: Randomness) -> CreateCallLinkCredentialResponse {
        return failOnError {
            try withUnsafeBorrowedBuffer { contents in
                try userId.withPointerToFixedWidthBinary { userId in
                    try params.withUnsafeBorrowedBuffer { params in
                        try randomness.withUnsafePointerToBytes { randomness in
                            try invokeFnReturningVariableLengthSerialized {
                                signal_create_call_link_credential_request_issue_deterministic($0, contents, userId, UInt64(timestamp.timeIntervalSince1970), params, randomness)
                            }
                        }
                    }
                }
            }
        }
    }
}
