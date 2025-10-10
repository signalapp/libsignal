//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public struct IdentityKey: Equatable, Sendable {
    public let publicKey: PublicKey

    public init(publicKey: PublicKey) {
        self.publicKey = publicKey
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        self.publicKey = try PublicKey(bytes)
    }

    public func serialize() -> Data {
        return self.publicKey.serialize()
    }

    public func verifyAlternateIdentity<Bytes: ContiguousBytes>(_ other: IdentityKey, signature: Bytes) throws -> Bool {
        return try withAllBorrowed(publicKey, other.publicKey, .bytes(signature)) {
            selfHandle,
            otherHandle,
            signatureBuffer in
            try invokeFnReturningBool {
                signal_identitykey_verify_alternate_identity(
                    $0,
                    selfHandle.const(),
                    otherHandle.const(),
                    signatureBuffer
                )
            }
        }
    }
}

public struct IdentityKeyPair: Sendable {
    public let publicKey: PublicKey
    public let privateKey: PrivateKey

    public static func generate() -> IdentityKeyPair {
        let privateKey = PrivateKey.generate()
        let publicKey = privateKey.publicKey
        return IdentityKeyPair(publicKey: publicKey, privateKey: privateKey)
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let out = try bytes.withUnsafeBorrowedBuffer { bytes in
            try invokeFnReturningValueByPointer(.init()) {
                signal_identitykeypair_deserialize($0, bytes)
            }
        }

        self.publicKey = PublicKey(owned: NonNull(out.first)!)
        self.privateKey = PrivateKey(owned: NonNull(out.second)!)
    }

    public init(publicKey: PublicKey, privateKey: PrivateKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    public func serialize() -> Data {
        return failOnError {
            try withAllBorrowed(self.publicKey, self.privateKey) { publicKey, privateKey in
                try invokeFnReturningData {
                    signal_identitykeypair_serialize($0, publicKey.const(), privateKey.const())
                }
            }
        }
    }

    public var identityKey: IdentityKey {
        return IdentityKey(publicKey: self.publicKey)
    }

    public func signAlternateIdentity(_ other: IdentityKey) -> Data {
        return failOnError {
            try withAllBorrowed(self.publicKey, self.privateKey, other.publicKey) { publicKey, privateKey, other in
                try invokeFnReturningData {
                    signal_identitykeypair_sign_alternate_identity(
                        $0,
                        publicKey.const(),
                        privateKey.const(),
                        other.const()
                    )
                }
            }
        }
    }
}
