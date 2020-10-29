//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class SignedPreKeyRecord: ClonableHandleOwner {
    internal override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_signed_pre_key_record_destroy(handle)
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_signed_pre_key_record_clone(&newHandle, currentHandle)
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_signed_pre_key_record_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
        super.init(owned: handle!)
    }

    public init<Bytes: ContiguousBytes>(id: UInt32,
                                        timestamp: UInt64,
                                        privateKey: PrivateKey,
                                        signature: Bytes) throws {
        let publicKey = try privateKey.publicKey()
        let handle: OpaquePointer? = try signature.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_signed_pre_key_record_new(&result, id, timestamp,
                                                            publicKey.nativeHandle, privateKey.nativeHandle,
                                                            $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
        super.init(owned: handle!)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    public func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_signed_pre_key_record_serialize(nativeHandle, $0, $1)
        }
    }

    public func id() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_signed_pre_key_record_get_id(nativeHandle, $0)
        }
    }

    public func timestamp() throws -> UInt64 {
        return try invokeFnReturningInteger {
            signal_signed_pre_key_record_get_timestamp(nativeHandle, $0)
        }
    }

    public func publicKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey {
            signal_signed_pre_key_record_get_public_key($0, nativeHandle)
        }
    }

    public func privateKey() throws -> PrivateKey {
        return try invokeFnReturningPrivateKey {
            signal_signed_pre_key_record_get_private_key($0, nativeHandle)
        }
    }

    public func signature() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_signed_pre_key_record_get_signature(nativeHandle, $0, $1)
        }
    }
}
