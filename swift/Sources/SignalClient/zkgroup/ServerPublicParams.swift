//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ServerPublicParams: ByteArray {

  public static let SIZE: Int = 225

  public required init(contents: [UInt8]) throws {
    try super.init(newContents: contents, expectedLength: ServerPublicParams.SIZE, unrecoverable: true)

    try withUnsafePointerToSerialized { contents in
      try checkError(signal_server_public_params_check_valid_contents(contents))
    }
  }

  public func verifySignature(message: [UInt8], notarySignature: NotarySignature) throws {
    try withUnsafePointerToSerialized { contents in
      try notarySignature.withUnsafePointerToSerialized { notarySignature in
        try checkError(signal_server_public_params_verify_signature(contents, message, message.count, notarySignature))
      }
    }
  }

}
