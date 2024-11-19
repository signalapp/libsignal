//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ServerZkAuthOperations {
    let serverSecretParams: ServerSecretParams

    public init(serverSecretParams: ServerSecretParams) {
        self.serverSecretParams = serverSecretParams
    }

    @available(*, deprecated, message: "these credentials are no longer supported by the server; use issueAuthCredentialWithPniZkc instead")
    public func issueAuthCredentialWithPniAsServiceId(aci: Aci, pni: Pni, redemptionTime: UInt64) throws -> AuthCredentialWithPniResponse {
        return try self.issueAuthCredentialWithPniAsServiceId(randomness: Randomness.generate(), aci: aci, pni: pni, redemptionTime: redemptionTime)
    }

    @available(*, deprecated, message: "these credentials are no longer supported by the server; use issueAuthCredentialWithPniZkc instead")
    public func issueAuthCredentialWithPniAsServiceId(randomness: Randomness, aci: Aci, pni: Pni, redemptionTime: UInt64) throws -> AuthCredentialWithPniResponse {
        return try self.serverSecretParams.withNativeHandle { serverSecretParams in
            try randomness.withUnsafePointerToBytes { randomness in
                try aci.withPointerToFixedWidthBinary { aci in
                    try pni.withPointerToFixedWidthBinary { pni in
                        try invokeFnReturningVariableLengthSerialized {
                            signal_server_secret_params_issue_auth_credential_with_pni_as_service_id_deterministic($0, serverSecretParams, randomness, aci, pni, redemptionTime)
                        }
                    }
                }
            }
        }
    }

    public func issueAuthCredentialWithPniZkc(aci: Aci, pni: Pni, redemptionTime: UInt64) throws -> AuthCredentialWithPniResponse {
        return try self.issueAuthCredentialWithPniZkc(randomness: Randomness.generate(), aci: aci, pni: pni, redemptionTime: redemptionTime)
    }

    public func issueAuthCredentialWithPniZkc(randomness: Randomness, aci: Aci, pni: Pni, redemptionTime: UInt64) throws -> AuthCredentialWithPniResponse {
        return try self.serverSecretParams.withNativeHandle { serverSecretParams in
            try randomness.withUnsafePointerToBytes { randomness in
                try aci.withPointerToFixedWidthBinary { aci in
                    try pni.withPointerToFixedWidthBinary { pni in
                        try invokeFnReturningVariableLengthSerialized {
                            signal_server_secret_params_issue_auth_credential_with_pni_zkc_deterministic($0, serverSecretParams, randomness, aci, pni, redemptionTime)
                        }
                    }
                }
            }
        }
    }

    public func verifyAuthCredentialPresentation(groupPublicParams: GroupPublicParams, authCredentialPresentation: AuthCredentialPresentation, now: Date = Date()) throws {
        try self.serverSecretParams.withNativeHandle { serverSecretParams in
            try groupPublicParams.withUnsafePointerToSerialized { groupPublicParams in
                try authCredentialPresentation.withUnsafeBorrowedBuffer { authCredentialPresentation in
                    try checkError(signal_server_secret_params_verify_auth_credential_presentation(serverSecretParams, groupPublicParams, authCredentialPresentation, UInt64(now.timeIntervalSince1970)))
                }
            }
        }
    }
}
