//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ProfileKeyCredentialPresentation: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_profile_key_credential_presentation_check_valid_contents)
  }

  public func getUuidCiphertext() throws -> UuidCiphertext {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningSerialized {
        signal_profile_key_credential_presentation_get_uuid_ciphertext($0, contents)
      }
    }
  }

  public func getProfileKeyCiphertext() throws -> ProfileKeyCiphertext {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningSerialized {
        signal_profile_key_credential_presentation_get_profile_key_ciphertext($0, contents)
      }
    }
  }

}
