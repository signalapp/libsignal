//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ClientZkProfileOperations {
    let serverPublicParams: ServerPublicParams

    public init(serverPublicParams: ServerPublicParams) {
        self.serverPublicParams = serverPublicParams
    }

    public func createProfileKeyCredentialRequestContext(userId: Aci, profileKey: ProfileKey) throws -> ProfileKeyCredentialRequestContext {
        return try self.createProfileKeyCredentialRequestContext(randomness: Randomness.generate(), userId: userId, profileKey: profileKey)
    }

    public func createProfileKeyCredentialRequestContext(randomness: Randomness, userId: Aci, profileKey: ProfileKey) throws -> ProfileKeyCredentialRequestContext {
        return try self.serverPublicParams.withNativeHandle { serverPublicParams in
            try randomness.withUnsafePointerToBytes { randomness in
                try userId.withPointerToFixedWidthBinary { userId in
                    try profileKey.withUnsafePointerToSerialized { profileKey in
                        try invokeFnReturningSerialized {
                            signal_server_public_params_create_profile_key_credential_request_context_deterministic($0, serverPublicParams, randomness, userId, profileKey)
                        }
                    }
                }
            }
        }
    }

    public func receiveExpiringProfileKeyCredential(
        profileKeyCredentialRequestContext: ProfileKeyCredentialRequestContext,
        profileKeyCredentialResponse: ExpiringProfileKeyCredentialResponse,
        now: Date = Date()
    ) throws -> ExpiringProfileKeyCredential {
        return try self.serverPublicParams.withNativeHandle { serverPublicParams in
            try profileKeyCredentialRequestContext.withUnsafePointerToSerialized { requestContext in
                try profileKeyCredentialResponse.withUnsafePointerToSerialized { response in
                    try invokeFnReturningSerialized {
                        signal_server_public_params_receive_expiring_profile_key_credential($0, serverPublicParams, requestContext, response, UInt64(now.timeIntervalSince1970))
                    }
                }
            }
        }
    }

    public func createProfileKeyCredentialPresentation(groupSecretParams: GroupSecretParams, profileKeyCredential: ExpiringProfileKeyCredential) throws -> ProfileKeyCredentialPresentation {
        return try self.createProfileKeyCredentialPresentation(randomness: Randomness.generate(), groupSecretParams: groupSecretParams, profileKeyCredential: profileKeyCredential)
    }

    public func createProfileKeyCredentialPresentation(randomness: Randomness, groupSecretParams: GroupSecretParams, profileKeyCredential: ExpiringProfileKeyCredential) throws -> ProfileKeyCredentialPresentation {
        return try self.serverPublicParams.withNativeHandle { serverPublicParams in
            try randomness.withUnsafePointerToBytes { randomness in
                try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
                    try profileKeyCredential.withUnsafePointerToSerialized { profileKeyCredential in
                        try invokeFnReturningVariableLengthSerialized {
                            signal_server_public_params_create_expiring_profile_key_credential_presentation_deterministic($0, serverPublicParams, randomness, groupSecretParams, profileKeyCredential)
                        }
                    }
                }
            }
        }
    }
}
