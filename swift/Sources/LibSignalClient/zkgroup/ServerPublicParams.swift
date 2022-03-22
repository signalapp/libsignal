//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ServerPublicParams: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_server_public_params_check_valid_contents)
  }

  public func verifySignature(message: [UInt8], notarySignature: NotarySignature) throws {
    try withUnsafePointerToSerialized { contents in
      try message.withUnsafeBorrowedBuffer { message in
        try notarySignature.withUnsafePointerToSerialized { notarySignature in
          try checkError(signal_server_public_params_verify_signature(contents, message, notarySignature))
        }
      }
    }
  }

}
