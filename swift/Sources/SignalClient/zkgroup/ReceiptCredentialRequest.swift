//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//
// Generated by zkgroup/codegen/codegen.py - do not edit

import Foundation
import SignalFfi

public class ReceiptCredentialRequest : ByteArray {

  public static let SIZE: Int = 97

  public required init(contents: [UInt8]) throws  {
    try super.init(newContents: contents, expectedLength: ReceiptCredentialRequest.SIZE)

    try withUnsafePointerToSerialized { contents in
      try checkError(signal_receipt_credential_request_check_valid_contents(contents))
    }
  }

}
