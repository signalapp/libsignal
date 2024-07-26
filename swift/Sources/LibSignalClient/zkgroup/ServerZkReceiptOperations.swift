//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ServerZkReceiptOperations {
    let serverSecretParams: ServerSecretParams

    public init(serverSecretParams: ServerSecretParams) {
        self.serverSecretParams = serverSecretParams
    }

    public func issueReceiptCredential(receiptCredentialRequest: ReceiptCredentialRequest, receiptExpirationTime: UInt64, receiptLevel: UInt64) throws -> ReceiptCredentialResponse {
        return try self.issueReceiptCredential(randomness: Randomness.generate(), receiptCredentialRequest: receiptCredentialRequest, receiptExpirationTime: receiptExpirationTime, receiptLevel: receiptLevel)
    }

    public func issueReceiptCredential(randomness: Randomness, receiptCredentialRequest: ReceiptCredentialRequest, receiptExpirationTime: UInt64, receiptLevel: UInt64) throws -> ReceiptCredentialResponse {
        return try self.serverSecretParams.withNativeHandle { serverSecretParams in
            try randomness.withUnsafePointerToBytes { randomness in
                try receiptCredentialRequest.withUnsafePointerToSerialized { receiptCredentialRequest in
                    try invokeFnReturningSerialized {
                        signal_server_secret_params_issue_receipt_credential_deterministic($0, serverSecretParams, randomness, receiptCredentialRequest, receiptExpirationTime, receiptLevel)
                    }
                }
            }
        }
    }

    public func verifyReceiptCredentialPresentation(receiptCredentialPresentation: ReceiptCredentialPresentation) throws {
        try self.serverSecretParams.withNativeHandle { serverSecretParams in
            try receiptCredentialPresentation.withUnsafePointerToSerialized { receiptCredentialPresentation in
                try checkError(signal_server_secret_params_verify_receipt_credential_presentation(serverSecretParams, receiptCredentialPresentation))
            }
        }
    }
}
