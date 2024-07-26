//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ServerZkProfileOperations {
    let serverSecretParams: ServerSecretParams

    public init(serverSecretParams: ServerSecretParams) {
        self.serverSecretParams = serverSecretParams
    }

    public func issueExpiringProfileKeyCredential(profileKeyCredentialRequest: ProfileKeyCredentialRequest, userId: Aci, profileKeyCommitment: ProfileKeyCommitment, expiration: UInt64) throws -> ExpiringProfileKeyCredentialResponse {
        return try self.issueExpiringProfileKeyCredential(randomness: Randomness.generate(), profileKeyCredentialRequest: profileKeyCredentialRequest, userId: userId, profileKeyCommitment: profileKeyCommitment, expiration: expiration)
    }

    public func issueExpiringProfileKeyCredential(randomness: Randomness, profileKeyCredentialRequest: ProfileKeyCredentialRequest, userId: Aci, profileKeyCommitment: ProfileKeyCommitment, expiration: UInt64) throws -> ExpiringProfileKeyCredentialResponse {
        return try self.serverSecretParams.withNativeHandle { serverSecretParams in
            try randomness.withUnsafePointerToBytes { randomness in
                try profileKeyCredentialRequest.withUnsafePointerToSerialized { request in
                    try userId.withPointerToFixedWidthBinary { userId in
                        try profileKeyCommitment.withUnsafePointerToSerialized { commitment in
                            try invokeFnReturningSerialized {
                                signal_server_secret_params_issue_expiring_profile_key_credential_deterministic($0, serverSecretParams, randomness, request, userId, commitment, expiration)
                            }
                        }
                    }
                }
            }
        }
    }

    public func verifyProfileKeyCredentialPresentation(
        groupPublicParams: GroupPublicParams,
        profileKeyCredentialPresentation: ProfileKeyCredentialPresentation,
        now: Date = Date()
    ) throws {
        try self.serverSecretParams.withNativeHandle { serverSecretParams in
            try groupPublicParams.withUnsafePointerToSerialized { groupPublicParams in
                try profileKeyCredentialPresentation.withUnsafeBorrowedBuffer { presentation in
                    try checkError(signal_server_secret_params_verify_profile_key_credential_presentation(serverSecretParams, groupPublicParams, presentation, UInt64(now.timeIntervalSince1970)))
                }
            }
        }
    }
}
