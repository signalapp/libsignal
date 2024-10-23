//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

public class GroupIdentifier: ByteArray, @unchecked Sendable {
    public static let SIZE: Int = 32

    public required init(contents: [UInt8]) throws {
        try super.init(newContents: contents, expectedLength: GroupIdentifier.SIZE)
    }
}
