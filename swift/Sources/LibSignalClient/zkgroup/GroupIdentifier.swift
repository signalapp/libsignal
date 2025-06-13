//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class GroupIdentifier: ByteArray, CustomStringConvertible, @unchecked Sendable {
    public static let SIZE: Int = 32

    public required init(contents: Data) throws {
        try super.init(newContents: contents, expectedLength: GroupIdentifier.SIZE)
    }

    /// Returns the group ID as (lowercase) hexadecimal
    public var description: String {
        self.serialize().toHex()
    }
}
