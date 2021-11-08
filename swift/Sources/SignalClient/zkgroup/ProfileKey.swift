//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ProfileKey: ByteArray {

  public static let SIZE: Int = 32

  public required init(contents: [UInt8]) throws {
    try super.init(newContents: contents, expectedLength: ProfileKey.SIZE)
  }

  public func getCommitment(uuid: UUID) throws -> ProfileKeyCommitment {
    return try withUnsafePointerToSerialized { contents in
      try withUnsafePointer(to: uuid.uuid) { uuid in
        try invokeFnReturningSerialized {
          signal_profile_key_get_commitment($0, contents, uuid)
        }
      }
    }
  }

  public func getProfileKeyVersion(uuid: UUID) throws -> ProfileKeyVersion {
    return try withUnsafePointerToSerialized { contents in
      try withUnsafePointer(to: uuid.uuid) { uuid in
        try invokeFnReturningSerialized {
          signal_profile_key_get_profile_key_version($0, contents, uuid)
        }
      }
    }
  }

}
