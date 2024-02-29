//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/**
 * A credential indicating membership in a group, based on the set of *other* users in the
 * group with you.
 *
 * Follows the usual zkgroup pattern of "issue response -> receive response -> present credential
 * -> verify presentation".
 *
 * - SeeAlso: ``GroupSendCredentialResponse``, ``GroupSendCredential``
 */
public class GroupSendCredentialPresentation: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_group_send_credential_presentation_check_valid_contents)
  }

  /**
   * Verifies that the credential is valid for a group containing the holder and `groupMembers`.
   *
   * - Throws: ``SignalError/verificationFailed(_:)`` if the credential is not valid for any reason
   */
  public func verify(groupMembers: [ServiceId], now: Date = Date(), serverParams: ServerSecretParams) throws {
    try withUnsafeBorrowedBuffer { contents in
      try ServiceId.concatenatedFixedWidthBinary(groupMembers).withUnsafeBorrowedBuffer { groupMembers in
        try serverParams.withUnsafePointerToSerialized { serverParams in
          try checkError(signal_group_send_credential_presentation_verify(contents, groupMembers, UInt64(now.timeIntervalSince1970), serverParams))
        }
      }
    }
  }
}
