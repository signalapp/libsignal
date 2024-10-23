//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class CallLinkAuthCredentialResponse: ByteArray, @unchecked Sendable {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: signal_call_link_auth_credential_response_check_valid_contents)
    }

    public static func issueCredential(userId: Aci, redemptionTime: Date, params: GenericServerSecretParams) -> CallLinkAuthCredentialResponse {
        return failOnError {
            self.issueCredential(userId: userId, redemptionTime: redemptionTime, params: params, randomness: try .generate())
        }
    }

    public static func issueCredential(userId: Aci, redemptionTime: Date, params: GenericServerSecretParams, randomness: Randomness) -> CallLinkAuthCredentialResponse {
        return failOnError {
            try userId.withPointerToFixedWidthBinary { userId in
                try params.withUnsafeBorrowedBuffer { params in
                    try randomness.withUnsafePointerToBytes { randomness in
                        try invokeFnReturningVariableLengthSerialized {
                            signal_call_link_auth_credential_response_issue_deterministic($0, userId, UInt64(redemptionTime.timeIntervalSince1970), params, randomness)
                        }
                    }
                }
            }
        }
    }

    public func receive(userId: Aci, redemptionTime: Date, params: GenericServerPublicParams) throws -> CallLinkAuthCredential {
        return try withUnsafeBorrowedBuffer { contents in
            try userId.withPointerToFixedWidthBinary { userId in
                try params.withUnsafeBorrowedBuffer { params in
                    try invokeFnReturningVariableLengthSerialized {
                        signal_call_link_auth_credential_response_receive($0, contents, userId, UInt64(redemptionTime.timeIntervalSince1970), params)
                    }
                }
            }
        }
    }
}
