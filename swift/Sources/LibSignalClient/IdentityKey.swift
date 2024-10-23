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

    public func serialize() -> [UInt8] {
        return self.publicKey.serialize()
    }

    public func verifyAlternateIdentity<Bytes: ContiguousBytes>(_ other: IdentityKey, signature: Bytes) throws -> Bool {
        var result = false
        try withNativeHandles(publicKey, other.publicKey) { selfHandle, otherHandle in
            try signature.withUnsafeBorrowedBuffer { signatureBuffer in
                try checkError(signal_identitykey_verify_alternate_identity(&result, selfHandle, otherHandle, signatureBuffer))
            }
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
        var pubkeyPtr: OpaquePointer?
        var privkeyPtr: OpaquePointer?
        try bytes.withUnsafeBorrowedBuffer {
            try checkError(signal_identitykeypair_deserialize(&privkeyPtr, &pubkeyPtr, $0))
        }

        self.publicKey = PublicKey(owned: pubkeyPtr!)
        self.privateKey = PrivateKey(owned: privkeyPtr!)
    }

    public init(publicKey: PublicKey, privateKey: PrivateKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    public func serialize() -> [UInt8] {
        return withNativeHandles(self.publicKey, self.privateKey) { publicKey, privateKey in
            failOnError {
                try invokeFnReturningArray {
                    signal_identitykeypair_serialize($0, publicKey, privateKey)
                }
            }
        }
    }

    public var identityKey: IdentityKey {
        return IdentityKey(publicKey: self.publicKey)
    }

    public func signAlternateIdentity(_ other: IdentityKey) -> [UInt8] {
        return withNativeHandles(self.publicKey, self.privateKey, other.publicKey) { publicKey, privateKey, other in
            failOnError {
                try invokeFnReturningArray {
                    signal_identitykeypair_sign_alternate_identity($0, publicKey, privateKey, other)
                }
            }
        }
    }
}
