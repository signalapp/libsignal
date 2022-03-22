//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class AuthCredentialPresentation: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_auth_credential_presentation_check_valid_contents)
  }

  public func getUuidCiphertext() throws -> UuidCiphertext {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningSerialized {
        signal_auth_credential_presentation_get_uuid_ciphertext($0, contents)
      }
    }
  }

  public func getRedemptionTime() throws -> UInt32 {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningInteger {
        signal_auth_credential_presentation_get_redemption_time($0, contents)
      }
    }
  }

}
