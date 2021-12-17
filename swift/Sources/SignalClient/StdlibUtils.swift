//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

extension MutableCollection where Self: ContiguousBytes, Self.Element == UInt8 {
    /// Like withContiguousMutableStorageIfAvailable, but aborts if it's not available.
    internal mutating func withContiguousMutableStorage<R>(
        _ body: (inout UnsafeMutableBufferPointer<Self.Element>) throws -> R
    ) rethrows -> R {
        if let result = try! self.withContiguousMutableStorageIfAvailable(body) {
            return result
        }
        preconditionFailure("\(type(of: self)) does not have contiguous storage")
    }
}
