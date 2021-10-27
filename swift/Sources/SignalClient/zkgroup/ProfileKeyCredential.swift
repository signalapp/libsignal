//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ProfileKeyCredential: ByteArray {
  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_profile_key_credential_check_valid_contents)
  }
}
