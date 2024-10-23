//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ProfileKey: ByteArray, @unchecked Sendable {
    public static let SIZE: Int = 32

    public required init(contents: [UInt8]) throws {
        try super.init(newContents: contents, expectedLength: ProfileKey.SIZE)
    }

    public func getCommitment(userId: Aci) throws -> ProfileKeyCommitment {
        return try withUnsafePointerToSerialized { contents in
            try userId.withPointerToFixedWidthBinary { userId in
                try invokeFnReturningSerialized {
                    signal_profile_key_get_commitment($0, contents, userId)
                }
            }
        }
    }

    public func getProfileKeyVersion(userId: Aci) throws -> ProfileKeyVersion {
        return try withUnsafePointerToSerialized { contents in
            try userId.withPointerToFixedWidthBinary { userId in
                try invokeFnReturningSerialized {
                    signal_profile_key_get_profile_key_version($0, contents, userId)
                }
            }
        }
    }

    public func deriveAccessKey() -> [UInt8] {
        return failOnError {
            try withUnsafePointerToSerialized { contents in
                try invokeFnReturningFixedLengthArray {
                    signal_profile_key_derive_access_key($0, contents)
                }
            }
        }
    }
}
