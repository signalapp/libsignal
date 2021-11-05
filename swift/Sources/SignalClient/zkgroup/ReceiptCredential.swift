//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ReceiptCredential: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_receipt_credential_check_valid_contents)
  }

  public func getReceiptExpirationTime() throws -> UInt64 {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningInteger {
        signal_receipt_credential_get_receipt_expiration_time($0, contents)
      }
    }
  }

  public func getReceiptLevel() throws -> UInt64 {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningInteger {
        signal_receipt_credential_get_receipt_level($0, contents)
      }
    }
  }

}
