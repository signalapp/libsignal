//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ReceiptCredentialRequestContext: ByteArray {

  public static let SIZE: Int = 177

  public required init(contents: [UInt8]) throws {
    try super.init(newContents: contents, expectedLength: ReceiptCredentialRequestContext.SIZE)

    try withUnsafePointerToSerialized { contents in
      try checkError(signal_receipt_credential_request_context_check_valid_contents(contents))
    }
  }

  public func getRequest() throws -> ReceiptCredentialRequest {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningSerialized {
        signal_receipt_credential_request_context_get_request($0, contents)
      }
    }
  }

}
