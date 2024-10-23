//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public struct Username: Sendable {
    public let value: String
    public let hash: [UInt8]

    public init<S: StringProtocol>(_ s: S) throws {
        self.value = String(s)
        self.hash = try generateHash(self.value)
    }

    public init<
        LinkBytes: ContiguousBytes,
        RandBytes: ContiguousBytes
    >(
        fromLink bytes: LinkBytes,
        withRandomness randomness: RandBytes
    ) throws {
        let username =
            try randomness.withUnsafeBorrowedBuffer { randBuffer in
                try bytes.withUnsafeBorrowedBuffer { bytesBuffer in
                    try invokeFnReturningString {
                        signal_username_link_decrypt_username($0, randBuffer, bytesBuffer)
                    }
                }
            }
        try self.init(username)
    }

    public init(nickname: String, discriminator: String, withValidLengthWithin lengthRange: ClosedRange<UInt32>) throws {
        self.hash = try nickname.withCString { nickname in
            try discriminator.withCString { discriminator in
                try invokeFnReturningFixedLengthArray {
                    signal_username_hash_from_parts($0, nickname, discriminator, lengthRange.lowerBound, lengthRange.upperBound)
                }
            }
        }
        // If we generated the hash correctly, we can format the nickname and discriminator manually.
        self.value = "\(nickname).\(discriminator)"
    }

    public func generateProof(withRandomness randomness: Randomness? = nil) -> [UInt8] {
        failOnError {
            let randomness = try randomness ?? Randomness.generate()
            return try self.value.withCString { strPtr in
                try withUnsafeBytes(of: randomness.bytes) { randBytes in
                    try randBytes.withUnsafeBorrowedBuffer { randPtr in
                        try invokeFnReturningArray {
                            signal_username_proof($0, strPtr, randPtr)
                        }
                    }
                }
            }
        }
    }

    public func createLink(previousEntropy: [UInt8]? = nil) throws -> ([UInt8], [UInt8]) {
        let bytes = failOnError {
            try self.value.withCString { usernamePtr in
                try (previousEntropy ?? []).withUnsafeBorrowedBuffer { entropyPtr in
                    try invokeFnReturningArray {
                        signal_username_link_create($0, usernamePtr, entropyPtr)
                    }
                }
            }
        }
        return (Array(bytes[..<32]), Array(bytes[32...]))
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
            try invokeFnReturningStringArray {
                signal_username_candidates_from($0, nicknamePtr, lengthRange.lowerBound, lengthRange.upperBound)
            }
        }
        return try allCandidates.map { try Username($0) }
    }
}

extension Username: CustomStringConvertible {
    public var description: String {
        return self.value
    }
}

extension Username: Equatable {}

private func generateHash(_ s: String) throws -> [UInt8] {
    try s.withCString { strPtr in
        try invokeFnReturningFixedLengthArray {
            signal_username_hash($0, strPtr)
        }
    }
}
