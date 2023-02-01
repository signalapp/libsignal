//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public struct Username {
    public let value: String
    public let hash: [UInt8]

    public init<S: StringProtocol>(_ s: S) throws {
        self.value = String(s)
        self.hash = try generateHash(self.value)
    }

    public func generateProof(withRandomness randomness: Randomness? = nil) -> [UInt8] {
        failOnError {
            let randomness = try randomness ?? Randomness.generate()
            return try self.value.withCString { strPtr in
                try withUnsafeBytes(of: randomness.bytes) { randBytes in
                    try randBytes.withUnsafeBorrowedBuffer { randPtr in
                        try invokeFnReturningArray {
                            signal_username_proof($0, $1, strPtr, randPtr)
                        }
                    }
                }
            }
        }
    }

    public static func verify(proof: [UInt8], forHash hash: [UInt8]) throws {
        try checkError(
            proof.withUnsafeBorrowedBuffer { proofPtr in
                hash.withUnsafeBorrowedBuffer { hashPtr in
                    signal_username_verify(proofPtr, hashPtr)
                }
            }
        )
    }

    public static func candidates(
            from nickname: String,
            withValidLengthWithin lengthRange: ClosedRange<UInt32> = 3...32
    ) throws -> [Username] {
        let allCandidates = try nickname.withCString { nicknamePtr in
            try invokeFnReturningString {
                signal_username_candidates_from($0, nicknamePtr, lengthRange.lowerBound, lengthRange.upperBound)
            }
        }
        return try allCandidates.split(separator: ",").map { try Username($0) }
    }
}

extension Username: CustomStringConvertible {
    public var description: String {
        return value
    }
}

private func generateHash(_ s: String) throws -> [UInt8] {
    try s.withCString { strPtr in
        try invokeFnReturningArray {
            signal_username_hash($0, $1, strPtr)
        }
    }
}
