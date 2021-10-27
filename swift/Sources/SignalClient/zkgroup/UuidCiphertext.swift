//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class UuidCiphertext: ByteArray {

  public static let SIZE: Int = 65

  public required init(contents: [UInt8]) throws {
    try super.init(newContents: contents, expectedLength: UuidCiphertext.SIZE)

    try self.withUnsafePointerToSerialized { contents in
      try checkError(signal_uuid_ciphertext_check_valid_contents(contents))
    }
  }

}
