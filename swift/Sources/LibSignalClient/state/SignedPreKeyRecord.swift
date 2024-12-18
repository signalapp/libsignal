//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class SignedPreKeyRecord: ClonableHandleOwner<SignalMutPointerSignedPreKeyRecord> {
    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerSignedPreKeyRecord>) -> SignalFfiErrorRef? {
        return signal_signed_pre_key_record_destroy(handle.pointer)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout SignalMutPointerSignedPreKeyRecord, currentHandle: SignalConstPointerSignedPreKeyRecord) -> SignalFfiErrorRef? {
        return signal_signed_pre_key_record_clone(&newHandle, currentHandle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle = try bytes.withUnsafeBorrowedBuffer {
            var result = SignalMutPointerSignedPreKeyRecord()
            try checkError(signal_signed_pre_key_record_deserialize(&result, $0))
            return result
        }
        self.init(owned: NonNull(handle)!)
    }

    public convenience init<Bytes: ContiguousBytes>(
        id: UInt32,
        timestamp: UInt64,
        privateKey: PrivateKey,
        signature: Bytes
    ) throws {
        let publicKey = privateKey.publicKey
        var result = SignalMutPointerSignedPreKeyRecord()
        try withNativeHandles(publicKey, privateKey) { publicKeyHandle, privateKeyHandle in
            try signature.withUnsafeBorrowedBuffer {
                try checkError(signal_signed_pre_key_record_new(
                    &result,
                    id,
                    timestamp,
                    publicKeyHandle.const(),
                    privateKeyHandle.const(),
                    $0
                ))
            }
        }
        self.init(owned: NonNull(result)!)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_signed_pre_key_record_serialize($0, nativeHandle.const())
                }
            }
        }
    }

    public var id: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_signed_pre_key_record_get_id($0, nativeHandle.const())
                }
            }
        }
    }

    public var timestamp: UInt64 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_signed_pre_key_record_get_timestamp($0, nativeHandle.const())
                }
            }
        }
    }

    public func publicKey() throws -> PublicKey {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningNativeHandle {
                signal_signed_pre_key_record_get_public_key($0, nativeHandle.const())
            }
        }
    }

    public func privateKey() throws -> PrivateKey {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningNativeHandle {
                signal_signed_pre_key_record_get_private_key($0, nativeHandle.const())
            }
        }
    }

    public var signature: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_signed_pre_key_record_get_signature($0, nativeHandle.const())
                }
            }
        }
    }
}

extension SignalMutPointerSignedPreKeyRecord: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerSignedPreKeyRecord

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

extension SignalConstPointerSignedPreKeyRecord: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
