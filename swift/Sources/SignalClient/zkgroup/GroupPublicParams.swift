//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class GroupPublicParams: ByteArray {

  public static let SIZE: Int = 97

  public required init(contents: [UInt8]) throws {
    try super.init(newContents: contents, expectedLength: GroupPublicParams.SIZE)

    try withUnsafePointerToSerialized { contents in
      try checkError(signal_group_public_params_check_valid_contents(contents))
    }
  }

  public func getGroupIdentifier() throws -> GroupIdentifier {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningSerialized {
        signal_group_public_params_get_group_identifier($0, contents)
      }
    }
  }

}
