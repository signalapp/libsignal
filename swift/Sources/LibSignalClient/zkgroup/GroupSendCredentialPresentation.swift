//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class GroupSendCredentialPresentation: ByteArray {

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_group_send_credential_presentation_check_valid_contents)
  }

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
