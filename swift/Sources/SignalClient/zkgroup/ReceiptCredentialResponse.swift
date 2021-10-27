//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ReceiptCredentialResponse: ByteArray {

  public static let SIZE: Int = 409

  public required init(contents: [UInt8]) throws {
    try super.init(newContents: contents, expectedLength: ReceiptCredentialResponse.SIZE)

    try withUnsafePointerToSerialized { contents in
      try checkError(signal_receipt_credential_response_check_valid_contents(contents))
    }
  }

}
