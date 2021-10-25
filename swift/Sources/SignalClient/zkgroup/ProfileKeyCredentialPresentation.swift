//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//
// Generated by zkgroup/codegen/codegen.py - do not edit

import Foundation
import SignalFfi

public class ProfileKeyCredentialPresentation : ByteArray {

  public static let SIZE: Int = 713

  public required init(contents: [UInt8]) throws  {
    try super.init(newContents: contents, expectedLength: ProfileKeyCredentialPresentation.SIZE)

    try withUnsafePointerToSerialized { contents in
      try checkError(signal_profile_key_credential_presentation_check_valid_contents(contents))
    }
  }

  public func getUuidCiphertext() throws  -> UuidCiphertext {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningSerialized {
        signal_profile_key_credential_presentation_get_uuid_ciphertext($0, contents)
      }
    }
  }

  public func getProfileKeyCiphertext() throws  -> ProfileKeyCiphertext {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningSerialized {
        signal_profile_key_credential_presentation_get_profile_key_ciphertext($0, contents)
      }
    }
  }

}
