//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class AuthCredentialPresentation: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_auth_credential_presentation_check_valid_contents)
  }

  public func getUuidCiphertext() throws -> UuidCiphertext {
    return try withUnsafeBorrowedBuffer { buffer in
      try invokeFnReturningSerialized {
        signal_auth_credential_presentation_get_uuid_ciphertext($0, buffer)
      }
    }
  }

  public func getPniCiphertext() throws -> UuidCiphertext? {
    return try withUnsafeBorrowedBuffer { buffer in
      try invokeFnReturningOptionalVariableLengthSerialized {
        signal_auth_credential_presentation_get_pni_ciphertext_or_empty($0, buffer)
      }
    }
  }

  public func getRedemptionTime() throws -> Date {
    let secondsSinceEpoch = try withUnsafeBorrowedBuffer { buffer in
      try invokeFnReturningInteger {
        signal_auth_credential_presentation_get_redemption_time($0, buffer)
      }
    }
    return Date(timeIntervalSince1970: TimeInterval(secondsSinceEpoch))
  }

}
