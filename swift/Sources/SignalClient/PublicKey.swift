//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class PublicKey: ClonableHandleOwner {
    public init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_publickey_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
        super.init(owned: handle!)
    }

    internal override init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_publickey_destroy(handle)
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_publickey_clone(&newHandle, currentHandle)
    }

    public var keyBytes: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_publickey_get_public_key_bytes(nativeHandle, $0, $1)
            }
        }
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_publickey_serialize(nativeHandle, $0, $1)
            }
        }
    }

    public func verifySignature<MessageBytes, SignatureBytes>(message: MessageBytes, signature: SignatureBytes) throws -> Bool
    where MessageBytes: ContiguousBytes, SignatureBytes: ContiguousBytes {
        var result: Bool = false
        try message.withUnsafeBytes { messageBytes in
            try signature.withUnsafeBytes { signatureBytes in
                try checkError(signal_publickey_verify(&result, nativeHandle, messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), messageBytes.count, signatureBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), signatureBytes.count))
            }
        }
        return result
    }

    public func compare(_ other: PublicKey) -> Int32 {
        var result: Int32 = 0
        failOnError(signal_publickey_compare(&result, nativeHandle, other.nativeHandle))
        return result
    }
}

extension PublicKey: Equatable {
    public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.compare(rhs) == 0
    }
}

extension PublicKey: Comparable {
    public static func < (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.compare(rhs) < 0
    }
}
