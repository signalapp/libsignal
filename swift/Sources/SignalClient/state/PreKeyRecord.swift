//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class PreKeyRecord: ClonableHandleOwner {
    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_pre_key_record_destroy(handle)
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_pre_key_record_clone(&newHandle, currentHandle)
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_pre_key_record_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
        super.init(owned: handle!)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    public init(id: UInt32,
                publicKey: PublicKey,
                privateKey: PrivateKey) throws {
        var handle: OpaquePointer?
        try checkError(signal_pre_key_record_new(&handle, id, publicKey.nativeHandle, privateKey.nativeHandle))
        super.init(owned: handle!)
    }

    public convenience init(id: UInt32, privateKey: PrivateKey) throws {
        try self.init(id: id, publicKey: privateKey.publicKey, privateKey: privateKey)
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_pre_key_record_serialize($0, $1, nativeHandle)
            }
        }
    }

    public var id: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_pre_key_record_get_id($0, nativeHandle)
            }
        }
    }

    public var publicKey: PublicKey {
        return failOnError {
            try invokeFnReturningPublicKey {
                signal_pre_key_record_get_public_key($0, nativeHandle)
            }
        }
    }

    public var privateKey: PrivateKey {
        return failOnError {
            try invokeFnReturningPrivateKey {
                signal_pre_key_record_get_private_key($0, nativeHandle)
            }
        }
    }
}
