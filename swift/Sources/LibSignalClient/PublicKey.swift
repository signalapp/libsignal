//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class PublicKey: ClonableHandleOwner, @unchecked Sendable {
    public convenience init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(signal_publickey_deserialize(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_publickey_destroy(handle)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_publickey_clone(&newHandle, currentHandle)
    }

    public var keyBytes: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_publickey_get_public_key_bytes($0, nativeHandle)
                }
            }
        }
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_publickey_serialize($0, nativeHandle)
                }
            }
        }
    }

    public func verifySignature(message: some ContiguousBytes, signature: some ContiguousBytes) throws -> Bool {
        var result = false
        try withNativeHandle { nativeHandle in
            try message.withUnsafeBorrowedBuffer { messageBuffer in
                try signature.withUnsafeBorrowedBuffer { signatureBuffer in
                    try checkError(signal_publickey_verify(&result, nativeHandle, messageBuffer, signatureBuffer))
                }
            }
        }
        return result
    }

    public func compare(_ other: PublicKey) -> Int32 {
        var result: Int32 = 0
        withNativeHandles(self, other) { selfHandle, otherHandle in
            failOnError(signal_publickey_compare(&result, selfHandle, otherHandle))
        }
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
