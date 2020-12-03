//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public struct IdentityKey: Equatable {
    public let publicKey: PublicKey

    public init(publicKey: PublicKey) {
        self.publicKey = publicKey
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        publicKey = try PublicKey(bytes)
    }

    public func serialize() -> [UInt8] {
        return publicKey.serialize()
    }
}

public struct IdentityKeyPair {
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
        try bytes.withUnsafeBytes {
            try checkError(signal_identitykeypair_deserialize(&pubkeyPtr, &privkeyPtr, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
        }

        publicKey = PublicKey(owned: pubkeyPtr!)
        privateKey = PrivateKey(owned: privkeyPtr!)
    }

    public init(publicKey: PublicKey, privateKey: PrivateKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_identitykeypair_serialize($0, $1, publicKey.nativeHandle, privateKey.nativeHandle)
            }
        }
    }

    public var identityKey: IdentityKey {
        return IdentityKey(publicKey: publicKey)
    }
}
