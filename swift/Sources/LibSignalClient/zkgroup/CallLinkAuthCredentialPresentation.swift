//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class CallLinkAuthCredentialPresentation: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_call_link_auth_credential_presentation_check_valid_contents)
  }

  public func verify(now: Date = Date(), serverParams: GenericServerSecretParams, callLinkParams: CallLinkPublicParams) throws {
    try withUnsafeBorrowedBuffer { contents in
      try serverParams.withUnsafeBorrowedBuffer { serverParams in
        try callLinkParams.withUnsafeBorrowedBuffer { callLinkParams in
          try checkError(signal_call_link_auth_credential_presentation_verify(contents, UInt64(now.timeIntervalSince1970), serverParams, callLinkParams))
        }
      }
    }
  }

  public var userId: UuidCiphertext {
    return failOnError {
      try withUnsafeBorrowedBuffer { contents in
        try invokeFnReturningSerialized {
          signal_call_link_auth_credential_presentation_get_user_id($0, contents)
        }
      }
    }
  }
}
