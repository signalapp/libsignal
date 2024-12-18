//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class PreKeyRecord: ClonableHandleOwner<SignalMutPointerPreKeyRecord> {
    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerPreKeyRecord>) -> SignalFfiErrorRef? {
        return signal_pre_key_record_destroy(handle.pointer)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout SignalMutPointerPreKeyRecord, currentHandle: SignalConstPointerPreKeyRecord) -> SignalFfiErrorRef? {
        return signal_pre_key_record_clone(&newHandle, currentHandle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle: SignalMutPointerPreKeyRecord = try bytes.withUnsafeBorrowedBuffer {
            var result = SignalMutPointerPreKeyRecord()
            try checkError(signal_pre_key_record_deserialize(&result, $0))
            return result
        }
        self.init(owned: NonNull(handle)!)
    }

    public convenience init(
        id: UInt32,
        publicKey: PublicKey,
        privateKey: PrivateKey
    ) throws {
        var handle = SignalMutPointerPreKeyRecord()
        try withNativeHandles(publicKey, privateKey) { publicKeyHandle, privateKeyHandle in
            try checkError(signal_pre_key_record_new(&handle, id, publicKeyHandle.const(), privateKeyHandle.const()))
        }
        self.init(owned: NonNull(handle)!)
    }

    public convenience init(id: UInt32, privateKey: PrivateKey) throws {
        try self.init(id: id, publicKey: privateKey.publicKey, privateKey: privateKey)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
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
