//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Security

public struct Randomness {
    public var bytes: SignalRandomnessBytes

    public init(_ bytes: SignalRandomnessBytes) {
        self.bytes = bytes
    }

    static func generate() throws -> Randomness {
        var bytes: SignalRandomnessBytes = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        let result = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout.size(ofValue: bytes), &bytes)
        guard result == errSecSuccess else {
          throw SignalError.internalError("SecRandomCopyBytes failed (error code \(result))")
        }

        return Randomness(bytes)
    }

    func withUnsafePointerToBytes<Result>(_ callback: (UnsafePointer<SignalRandomnessBytes>) throws -> Result) rethrows -> Result {
        try withUnsafePointer(to: self.bytes, callback)
    }
}
