//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class PniCredentialPresentation: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_pni_credential_presentation_check_valid_contents)
  }

  public func getAciCiphertext() throws -> UuidCiphertext {
    return try withUnsafeBorrowedBuffer { buffer in
      try invokeFnReturningSerialized {
        signal_pni_credential_presentation_get_aci_ciphertext($0, buffer)
      }
    }
  }

  public func getPniCiphertext() throws -> UuidCiphertext {
    return try withUnsafeBorrowedBuffer { buffer in
      try invokeFnReturningSerialized {
        signal_pni_credential_presentation_get_pni_ciphertext($0, buffer)
      }
    }
  }

  public func getProfileKeyCiphertext() throws -> ProfileKeyCiphertext {
    return try withUnsafeBorrowedBuffer { buffer in
      try invokeFnReturningSerialized {
        signal_pni_credential_presentation_get_profile_key_ciphertext($0, buffer)
      }
    }
  }

}
