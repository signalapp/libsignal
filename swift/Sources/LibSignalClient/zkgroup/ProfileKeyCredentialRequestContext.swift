//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ProfileKeyCredentialRequestContext: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_profile_key_credential_request_context_check_valid_contents)
  }

  public func getRequest() throws -> ProfileKeyCredentialRequest {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningSerialized {
        signal_profile_key_credential_request_context_get_request($0, contents)
      }
    }
  }

}
