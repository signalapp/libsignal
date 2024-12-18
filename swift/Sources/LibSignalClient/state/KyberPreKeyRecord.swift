//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class KyberPreKeyRecord: ClonableHandleOwner<SignalMutPointerKyberPreKeyRecord> {
    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerKyberPreKeyRecord>) -> SignalFfiErrorRef? {
        return signal_kyber_pre_key_record_destroy(handle.pointer)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout SignalMutPointerKyberPreKeyRecord, currentHandle: SignalConstPointerKyberPreKeyRecord) -> SignalFfiErrorRef? {
        return signal_kyber_pre_key_record_clone(&newHandle, currentHandle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle = try bytes.withUnsafeBorrowedBuffer {
            var result = SignalMutPointerKyberPreKeyRecord()
            try checkError(signal_kyber_pre_key_record_deserialize(&result, $0))
            return result
        }
        self.init(owned: NonNull(handle)!)
    }

    public convenience init<Bytes: ContiguousBytes>(
        id: UInt32,
        timestamp: UInt64,
        keyPair: KEMKeyPair,
        signature: Bytes
    ) throws {
        var result = SignalMutPointerKyberPreKeyRecord()
        try keyPair.withNativeHandle { keyPairHandle in
            try signature.withUnsafeBorrowedBuffer {
                try checkError(signal_kyber_pre_key_record_new(&result, id, timestamp, keyPairHandle.const(), $0))
            }
        }
        self.init(owned: NonNull(result)!)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_kyber_pre_key_record_serialize($0, nativeHandle.const())
                }
            }
        }
    }

    public var id: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_kyber_pre_key_record_get_id($0, nativeHandle.const())
                }
            }
        }
    }

    public var timestamp: UInt64 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_kyber_pre_key_record_get_timestamp($0, nativeHandle.const())
                }
            }
        }
    }

    public func keyPair() throws -> KEMKeyPair {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningNativeHandle {
                signal_kyber_pre_key_record_get_key_pair($0, nativeHandle.const())
            }
        }
    }

    public func publicKey() throws -> KEMPublicKey {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningNativeHandle {
                signal_kyber_pre_key_record_get_public_key($0, nativeHandle.const())
            }
        }
    }

    public func secretKey() throws -> KEMSecretKey {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningNativeHandle {
                signal_kyber_pre_key_record_get_secret_key($0, nativeHandle.const())
            }
        }
    }

    public var signature: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_kyber_pre_key_record_get_signature($0, nativeHandle.const())
                }
            }
        }
    }
}

extension SignalMutPointerKyberPreKeyRecord: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerKyberPreKeyRecord

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

extension SignalConstPointerKyberPreKeyRecord: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
