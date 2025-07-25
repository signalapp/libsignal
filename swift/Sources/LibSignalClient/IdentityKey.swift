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
        var result = false
        try withAllBorrowed(publicKey, other.publicKey, .bytes(signature)) { selfHandle, otherHandle, signatureBuffer in
            try checkError(
                signal_identitykey_verify_alternate_identity(
                    &result,
                    selfHandle.const(),
                    otherHandle.const(),
                    signatureBuffer
                )
            )
        }
        return result
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
        var pubkeyPtr = SignalMutPointerPublicKey()
        var privkeyPtr = SignalMutPointerPrivateKey()
        try bytes.withUnsafeBorrowedBuffer {
            try checkError(signal_identitykeypair_deserialize(&privkeyPtr, &pubkeyPtr, $0))
        }

        self.publicKey = PublicKey(owned: NonNull(pubkeyPtr)!)
        self.privateKey = PrivateKey(owned: NonNull(privkeyPtr)!)
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
