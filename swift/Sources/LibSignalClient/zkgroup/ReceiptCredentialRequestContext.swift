//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ReceiptCredentialRequestContext: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_receipt_credential_request_context_check_valid_contents)
  }

  public func getRequest() throws -> ReceiptCredentialRequest {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningSerialized {
        signal_receipt_credential_request_context_get_request($0, contents)
      }
    }
  }

}
