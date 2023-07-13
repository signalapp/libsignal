//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class CallLinkAuthCredential: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_call_link_auth_credential_check_valid_contents)
  }

  public func present(userId: Aci, redemptionTime: Date, serverParams: GenericServerPublicParams, callLinkParams: CallLinkSecretParams) -> CallLinkAuthCredentialPresentation {
    return failOnError {
      present(userId: userId, redemptionTime: redemptionTime, serverParams: serverParams, callLinkParams: callLinkParams, randomness: try .generate())
    }
  }

  public func present(userId: Aci, redemptionTime: Date, serverParams: GenericServerPublicParams, callLinkParams: CallLinkSecretParams, randomness: Randomness) -> CallLinkAuthCredentialPresentation {
    return failOnError {
      try withUnsafeBorrowedBuffer { contents in
        try userId.withPointerToFixedWidthBinary { userId in
          try serverParams.withUnsafeBorrowedBuffer { serverParams in
            try callLinkParams.withUnsafeBorrowedBuffer { callLinkParams in
              try randomness.withUnsafePointerToBytes { randomness in
                try invokeFnReturningVariableLengthSerialized {
                  signal_call_link_auth_credential_present_deterministic($0, contents, userId, UInt64(redemptionTime.timeIntervalSince1970), serverParams, callLinkParams, randomness)
                }
              }
            }
          }
        }
      }
    }
  }

}
