//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class PreKeyRecord: ClonableHandleOwner<SignalMutPointerPreKeyRecord> {
    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerPreKeyRecord>
    ) -> SignalFfiErrorRef? {
        return signal_pre_key_record_destroy(handle.pointer)
    }

    override internal class func cloneNativeHandle(
        _ newHandle: inout SignalMutPointerPreKeyRecord,
        currentHandle: SignalConstPointerPreKeyRecord
    ) -> SignalFfiErrorRef? {
        return signal_pre_key_record_clone(&newHandle, currentHandle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle = try bytes.withUnsafeBorrowedBuffer { bytes in
            try invokeFnReturningValueByPointer(.init()) {
                signal_pre_key_record_deserialize($0, bytes)
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    public convenience init(
        id: UInt32,
        publicKey: PublicKey,
        privateKey: PrivateKey
    ) throws {
        let handle = try withAllBorrowed(publicKey, privateKey) { publicKeyHandle, privateKeyHandle in
            try invokeFnReturningValueByPointer(.init()) {
                signal_pre_key_record_new($0, id, publicKeyHandle.const(), privateKeyHandle.const())
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    public convenience init(id: UInt32, privateKey: PrivateKey) throws {
        try self.init(id: id, publicKey: privateKey.publicKey, privateKey: privateKey)
    }

    public func serialize() -> Data {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_pre_key_record_serialize($0, nativeHandle.const())
                }
            }
        }
    }

    public var id: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_pre_key_record_get_id($0, nativeHandle.const())
                }
            }
        }
    }

    public func publicKey() throws -> PublicKey {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningNativeHandle {
                signal_pre_key_record_get_public_key($0, nativeHandle.const())
            }
        }
    }

    public func privateKey() throws -> PrivateKey {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningNativeHandle {
                signal_pre_key_record_get_private_key($0, nativeHandle.const())
            }
        }
    }
}

extension SignalMutPointerPreKeyRecord: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerPreKeyRecord

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerPreKeyRecord: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
