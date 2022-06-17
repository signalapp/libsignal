//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ExpiringProfileKeyCredential: ByteArray {
  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_expiring_profile_key_credential_check_valid_contents)
  }

  public var expirationTime: Date {
    let timestampInSeconds = failOnError {
      try self.withUnsafePointerToSerialized { contents in
        try invokeFnReturningInteger {
          signal_expiring_profile_key_credential_get_expiration_time($0, contents)
        }
      }
    }
    return Date(timeIntervalSince1970: TimeInterval(timestampInSeconds))
  }
}
