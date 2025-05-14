//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum SignablePublicKey {
    case ecc(PublicKey)
    case kem(KEMPublicKey)

    public func withNativeTypes<Result>(fn: (UInt8, OpaquePointer) throws -> Result) rethrows -> Result {
        switch self {
        case .ecc(let key):
            try key.withNativeHandle {
                try fn(UInt8(SignalFfiPublicKeyTypeECC.rawValue), $0.raw)
            }
        case .kem(let key):
            try key.withNativeHandle {
                try fn(UInt8(SignalFfiPublicKeyTypeKyber.rawValue), $0.raw)
            }
        }
    }
}

public protocol SerializablePublicKey {
    func asSignable() -> SignablePublicKey
}

extension PublicKey: SerializablePublicKey {
    public func asSignable() -> SignablePublicKey {
        .ecc(self)
    }
}

extension KEMPublicKey: SerializablePublicKey {
    public func asSignable() -> SignablePublicKey {
        .kem(self)
    }
}

public struct SignedPublicPreKey<K: SerializablePublicKey & Sendable>: Sendable {
    public let keyId: UInt32
    public let publicKey: K
    public let signature: Data
    public init(keyId: UInt32, publicKey: K, signature: Data) {
        self.keyId = keyId
        self.publicKey = publicKey
        self.signature = signature
    }

    internal func withNativeStruct<Result>(fn: (SignalFfiSignedPublicPreKey) throws -> Result) rethrows -> Result {
        let publicKey = self.publicKey.asSignable()

        return try self.signature.withUnsafeBorrowedBuffer { signature in
            try publicKey.withNativeTypes { keyType, publicKey in
                let ffiStruct = SignalFfiSignedPublicPreKey(
                    key_id: self.keyId,
                    public_key_type: keyType,
                    public_key: UnsafeRawPointer(publicKey),
                    signature: signature
                )
                return try fn(ffiStruct)
            }
        }
    }
}
