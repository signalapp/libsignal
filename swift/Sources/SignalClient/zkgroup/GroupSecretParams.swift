//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class GroupSecretParams: ByteArray {

  public static func generate() throws -> GroupSecretParams {
    return try generate(randomness: Randomness.generate())
  }

  public static func generate(randomness: Randomness) throws -> GroupSecretParams {
    return try randomness.withUnsafePointerToBytes { randomness in
      try invokeFnReturningSerialized {
        signal_group_secret_params_generate_deterministic($0, randomness)
      }
    }
  }

  public static func deriveFromMasterKey(groupMasterKey: GroupMasterKey) throws -> GroupSecretParams {
    return try groupMasterKey.withUnsafePointerToSerialized { groupMasterKey in
      try invokeFnReturningSerialized {
        signal_group_secret_params_derive_from_master_key($0, groupMasterKey)
      }
    }
  }

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_group_secret_params_check_valid_contents)
  }

  public func getMasterKey() throws -> GroupMasterKey {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningSerialized {
        signal_group_secret_params_get_master_key($0, contents)
      }
    }
  }

  public func getPublicParams() throws -> GroupPublicParams {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningSerialized {
        signal_group_secret_params_get_public_params($0, contents)
      }
    }
  }

}
