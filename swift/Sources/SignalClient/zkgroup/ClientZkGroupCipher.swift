//
// Copyright 2020-2021 Signal Messenger, LLC.
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
    let paddedPlaintext = Array(repeating: 0, count: 4) + plaintext

    return try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try invokeFnReturningArray {
          signal_group_secret_params_encrypt_blob_deterministic($0, $1, groupSecretParams, randomness, paddedPlaintext, paddedPlaintext.count)
        }
      }
    }
  }

  public func decryptBlob(blobCiphertext: [UInt8]) throws -> [UInt8] {
    var newContents = try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
      try invokeFnReturningArray {
        signal_group_secret_params_decrypt_blob($0, $1, groupSecretParams, blobCiphertext, blobCiphertext.count)
      }
    }

    if newContents.count < 4 {
      throw SignalError.verificationFailed("decrypted ciphertext too short")
    }

    var paddingLen = newContents.withUnsafeBytes({ $0.load(fromByteOffset: 0, as: UInt32.self) })
    paddingLen = UInt32(bigEndian: paddingLen)

    if newContents.count < (4 + paddingLen) {
      throw SignalError.verificationFailed("decrypted ciphertext too short")
    }

    newContents.removeLast(Int(paddingLen))
    newContents.removeFirst(4)
    return newContents
  }

}
