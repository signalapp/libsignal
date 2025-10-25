//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public struct Username: Sendable {
    public let value: String
    public let hash: Data

    internal init(_ value: String, uncheckedHash: Data) {
        self.value = value
        self.hash = uncheckedHash
    }

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

    public init(nickname: String, discriminator: String, withValidLengthWithin lengthRange: ClosedRange<UInt32>) throws
    {
        self.hash = try nickname.withCString { nickname in
            try discriminator.withCString { discriminator in
                try invokeFnReturningFixedLengthArray {
                    signal_username_hash_from_parts(
                        $0,
                        nickname,
                        discriminator,
                        lengthRange.lowerBound,
                        lengthRange.upperBound
                    )
                }
            }
        }
        // If we generated the hash correctly, we can format the nickname and discriminator manually.
        self.value = "\(nickname).\(discriminator)"
    }

    public func generateProof(withRandomness randomness: Randomness? = nil) -> Data {
        failOnError {
            let randomness = try randomness ?? Randomness.generate()
            return try self.value.withCString { strPtr in
                try withUnsafePointer(to: randomness.bytes) { randomBytes in
                    try invokeFnReturningData {
                        signal_username_proof($0, strPtr, randomBytes)
                    }
                }
            }
        }
    }

    public func createLink(previousEntropy: Data? = nil) throws -> (Data, Data) {
        let bytes = failOnError {
            try self.value.withCString { usernamePtr in
                try (previousEntropy ?? Data()).withUnsafeBorrowedBuffer { entropyPtr in
                    try invokeFnReturningData {
                        signal_username_link_create($0, usernamePtr, entropyPtr)
                    }
                }
            }
        }
        return (bytes.subdata(in: 0..<32), bytes.subdata(in: 32..<bytes.count))
    }

    public static func verify(proof: Data, forHash hash: Data) throws {
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

private func generateHash(_ s: String) throws -> Data {
    try s.withCString { strPtr in
        try invokeFnReturningFixedLengthArray {
            signal_username_hash($0, strPtr)
        }
    }
}
