//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ReceiptCredentialRequest: ByteArray {

  public static let SIZE: Int = 97

  public required init(contents: [UInt8]) throws {
    try super.init(newContents: contents, expectedLength: ReceiptCredentialRequest.SIZE)

    try withUnsafePointerToSerialized { contents in
      try checkError(signal_receipt_credential_request_check_valid_contents(contents))
    }
  }

}
