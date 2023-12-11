//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class GroupSendCredential: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_group_send_credential_check_valid_contents)
  }

  public func present(serverParams: ServerPublicParams) -> GroupSendCredentialPresentation {
    return failOnError {
      present(serverParams: serverParams, randomness: try .generate())
    }
  }

  public func present(serverParams: ServerPublicParams, randomness: Randomness) -> GroupSendCredentialPresentation {
    return failOnError {
      try withUnsafeBorrowedBuffer { contents in
        try serverParams.withUnsafePointerToSerialized { serverParams in
          try randomness.withUnsafePointerToBytes { randomness in
            try invokeFnReturningVariableLengthSerialized {
              signal_group_send_credential_present_deterministic($0, contents, serverParams, randomness)
            }
          }
        }
      }
    }
  }
}
