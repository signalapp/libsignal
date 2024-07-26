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

    public func encrypt(_ serviceId: ServiceId) throws -> UuidCiphertext {
        return try self.groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
            try serviceId.withPointerToFixedWidthBinary { serviceId in
                try invokeFnReturningSerialized {
                    signal_group_secret_params_encrypt_service_id($0, groupSecretParams, serviceId)
                }
            }
        }
    }

    public func decrypt(_ uuidCiphertext: UuidCiphertext) throws -> ServiceId {
        return try self.groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
            try uuidCiphertext.withUnsafePointerToSerialized { uuidCiphertext in
                try invokeFnReturningServiceId {
                    signal_group_secret_params_decrypt_service_id($0, groupSecretParams, uuidCiphertext)
                }
            }
        }
    }

    public func encryptProfileKey(profileKey: ProfileKey, userId: Aci) throws -> ProfileKeyCiphertext {
        return try self.groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
            try profileKey.withUnsafePointerToSerialized { profileKey in
                try userId.withPointerToFixedWidthBinary { userId in
                    try invokeFnReturningSerialized {
                        signal_group_secret_params_encrypt_profile_key($0, groupSecretParams, profileKey, userId)
                    }
                }
            }
        }
    }

    public func decryptProfileKey(profileKeyCiphertext: ProfileKeyCiphertext, userId: Aci) throws -> ProfileKey {
        return try self.groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
            try profileKeyCiphertext.withUnsafePointerToSerialized { profileKeyCiphertext in
                try userId.withPointerToFixedWidthBinary { userId in
                    try invokeFnReturningSerialized {
                        signal_group_secret_params_decrypt_profile_key($0, groupSecretParams, profileKeyCiphertext, userId)
                    }
                }
            }
        }
    }

    public func encryptBlob(plaintext: [UInt8]) throws -> [UInt8] {
        return try self.encryptBlob(randomness: Randomness.generate(), plaintext: plaintext)
    }

    public func encryptBlob(randomness: Randomness, plaintext: [UInt8]) throws -> [UInt8] {
        return try self.groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
            try randomness.withUnsafePointerToBytes { randomness in
                try plaintext.withUnsafeBorrowedBuffer { plaintext in
                    try invokeFnReturningArray {
                        signal_group_secret_params_encrypt_blob_with_padding_deterministic($0, groupSecretParams, randomness, plaintext, 0)
                    }
                }
            }
        }
    }

    public func decryptBlob(blobCiphertext: [UInt8]) throws -> [UInt8] {
        return try self.groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
            try blobCiphertext.withUnsafeBorrowedBuffer { blobCiphertext in
                try invokeFnReturningArray {
                    signal_group_secret_params_decrypt_blob_with_padding($0, groupSecretParams, blobCiphertext)
                }
            }
        }
    }
}
