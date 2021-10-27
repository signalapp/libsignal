//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ProfileKeyCiphertext: ByteArray {

  public static let SIZE: Int = 65

  public required init(contents: [UInt8]) throws {
    try super.init(newContents: contents, expectedLength: ProfileKeyCiphertext.SIZE)

    try withUnsafePointerToSerialized { contents in
      try checkError(signal_profile_key_ciphertext_check_valid_contents(contents))
    }
  }

}
