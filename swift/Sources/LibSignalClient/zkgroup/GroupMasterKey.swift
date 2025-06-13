//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public class GroupMasterKey: ByteArray, @unchecked Sendable {
    public static let SIZE: Int = 32

    public required init(contents: Data) throws {
        try super.init(newContents: contents, expectedLength: GroupMasterKey.SIZE)
    }
}
