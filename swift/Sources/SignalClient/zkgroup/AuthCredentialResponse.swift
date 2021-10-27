//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class AuthCredentialResponse: ByteArray {

  public static let SIZE: Int = 361

  public required init(contents: [UInt8]) throws {
    try super.init(newContents: contents, expectedLength: AuthCredentialResponse.SIZE)

    try withUnsafePointerToSerialized { contents in
      try checkError(signal_auth_credential_response_check_valid_contents(contents))
    }
  }

}
