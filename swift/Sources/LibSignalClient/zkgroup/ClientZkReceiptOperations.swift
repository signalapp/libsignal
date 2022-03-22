//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ClientZkReceiptOperations {

  let serverPublicParams: ServerPublicParams

  public init(serverPublicParams: ServerPublicParams) {
    self.serverPublicParams = serverPublicParams
  }

  public func createReceiptCredentialRequestContext(receiptSerial: ReceiptSerial) throws -> ReceiptCredentialRequestContext {
    return try createReceiptCredentialRequestContext(randomness: Randomness.generate(), receiptSerial: receiptSerial)
  }

  public func createReceiptCredentialRequestContext(randomness: Randomness, receiptSerial: ReceiptSerial) throws -> ReceiptCredentialRequestContext {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try receiptSerial.withUnsafePointerToSerialized { receiptSerial in
          try invokeFnReturningSerialized {
            signal_server_public_params_create_receipt_credential_request_context_deterministic($0, serverPublicParams, randomness, receiptSerial)
          }
        }
      }
    }
  }

  public func receiveReceiptCredential(receiptCredentialRequestContext: ReceiptCredentialRequestContext, receiptCredentialResponse: ReceiptCredentialResponse) throws -> ReceiptCredential {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try receiptCredentialRequestContext.withUnsafePointerToSerialized { requestContext in
        try receiptCredentialResponse.withUnsafePointerToSerialized { response in
          try invokeFnReturningSerialized {
            signal_server_public_params_receive_receipt_credential($0, serverPublicParams, requestContext, response)
          }
        }
      }
    }
  }

  public func createReceiptCredentialPresentation(receiptCredential: ReceiptCredential) throws -> ReceiptCredentialPresentation {
    return try createReceiptCredentialPresentation(randomness: Randomness.generate(), receiptCredential: receiptCredential)
  }

  public func createReceiptCredentialPresentation(randomness: Randomness, receiptCredential: ReceiptCredential) throws -> ReceiptCredentialPresentation {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try receiptCredential.withUnsafePointerToSerialized { receiptCredential in
          try invokeFnReturningSerialized {
            signal_server_public_params_create_receipt_credential_presentation_deterministic($0, serverPublicParams, randomness, receiptCredential)
          }
        }
      }
    }
  }

}
