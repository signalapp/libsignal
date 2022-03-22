//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ClientZkGroupCipher {

  let groupSecretParams: GroupSecretParams

  public init(groupSecretParams: GroupSecretParams) {
    self.groupSecretParams = groupSecretParams
  }

  public func encryptUuid(uuid: UUID) throws -> UuidCiphertext {
    return try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
      try withUnsafePointer(to: uuid.uuid) { uuid in
        try invokeFnReturningSerialized {
          signal_group_secret_params_encrypt_uuid($0, groupSecretParams, uuid)
        }
      }
    }
  }

  public func decryptUuid(uuidCiphertext: UuidCiphertext) throws -> UUID {
    return try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
      try uuidCiphertext.withUnsafePointerToSerialized { uuidCiphertext in
        try invokeFnReturningUuid {
          signal_group_secret_params_decrypt_uuid($0, groupSecretParams, uuidCiphertext)
        }
      }
    }
  }

  public func encryptProfileKey(profileKey: ProfileKey, uuid: UUID) throws -> ProfileKeyCiphertext {
    return try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
      try profileKey.withUnsafePointerToSerialized { profileKey in
        try withUnsafePointer(to: uuid.uuid) { uuid in
          try invokeFnReturningSerialized {
            signal_group_secret_params_encrypt_profile_key($0, groupSecretParams, profileKey, uuid)
          }
        }
      }
    }
  }

  public func decryptProfileKey(profileKeyCiphertext: ProfileKeyCiphertext, uuid: UUID) throws -> ProfileKey {
    return try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
      try profileKeyCiphertext.withUnsafePointerToSerialized { profileKeyCiphertext in
        try withUnsafePointer(to: uuid.uuid) { uuid in
          try invokeFnReturningSerialized {
            signal_group_secret_params_decrypt_profile_key($0, groupSecretParams, profileKeyCiphertext, uuid)
          }
        }
      }
    }
  }

  public func encryptBlob(plaintext: [UInt8]) throws -> [UInt8] {
    return try encryptBlob(randomness: Randomness.generate(), plaintext: plaintext)
  }

  public func encryptBlob(randomness: Randomness, plaintext: [UInt8]) throws -> [UInt8] {
    return try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try plaintext.withUnsafeBorrowedBuffer { plaintext in
          try invokeFnReturningArray {
            signal_group_secret_params_encrypt_blob_with_padding_deterministic($0, $1, groupSecretParams, randomness, plaintext, 0)
          }
        }
      }
    }
  }

  public func decryptBlob(blobCiphertext: [UInt8]) throws -> [UInt8] {
    return try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
      try blobCiphertext.withUnsafeBorrowedBuffer { blobCiphertext in
        try invokeFnReturningArray {
          signal_group_secret_params_decrypt_blob_with_padding($0, $1, groupSecretParams, blobCiphertext)
        }
      }
    }
  }

}
