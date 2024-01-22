//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/**
 * A credential indicating membership in a group, based on the set of *other* users in the group
 * with you.
 *
 * Follows the usual zkgroup pattern of "issue response -> receive response -> present credential ->
 * verify presentation".
 *
 * - SeeAlso: ``GroupSendCredentialResponse``, ``GroupSendCredentialPresentation``
 */
public class GroupSendCredential: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_group_send_credential_check_valid_contents)
  }

  /**
   * Generates a new presentation, so that multiple uses of this credential are harder to link.
   */
  public func present(serverParams: ServerPublicParams) -> GroupSendCredentialPresentation {
    return failOnError {
      present(serverParams: serverParams, randomness: try .generate())
    }
  }

  /**
   * Generates a new presentation with a dedicated source of randomness.
   *
   * Should only be used for testing purposes.
   *
   * - SeeAlso: ``present(serverParams:)``
   */
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
