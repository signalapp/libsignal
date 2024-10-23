//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi

public struct Randomness: Sendable {
    public var bytes: SignalRandomnessBytes

    public init(_ bytes: SignalRandomnessBytes) {
        self.bytes = bytes
    }

    static func generate() throws -> Randomness {
        var bytes: SignalRandomnessBytes = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        try withUnsafeMutableBytes(of: &bytes) {
            try fillRandom($0)
        }
        return Randomness(bytes)
    }

    func withUnsafePointerToBytes<Result>(_ callback: (UnsafePointer<SignalRandomnessBytes>) throws -> Result) rethrows -> Result {
        try withUnsafePointer(to: self.bytes, callback)
    }
}
