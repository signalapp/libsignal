//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class KyberPreKeyRecord: ClonableHandleOwner {
    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_kyber_pre_key_record_destroy(handle)
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_kyber_pre_key_record_clone(&newHandle, currentHandle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(signal_kyber_pre_key_record_deserialize(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    public convenience init<Bytes: ContiguousBytes>(
        id: UInt32,
        timestamp: UInt64,
        keyPair: KEMKeyPair,
        signature: Bytes
    ) throws {
        var result: OpaquePointer?
        try keyPair.withNativeHandle { keyPairHandle in
            try signature.withUnsafeBorrowedBuffer {
                try checkError(signal_kyber_pre_key_record_new(&result, id, timestamp, keyPairHandle, $0))
            }
        }
        self.init(owned: result!)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_kyber_pre_key_record_serialize($0, nativeHandle)
                }
            }
        }
    }

    public var id: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_kyber_pre_key_record_get_id($0, nativeHandle)
                }
            }
        }
    }

    public var timestamp: UInt64 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_kyber_pre_key_record_get_timestamp($0, nativeHandle)
                }
            }
        }
    }

    public var keyPair: KEMKeyPair {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_kyber_pre_key_record_get_key_pair($0, nativeHandle)
                }
            }
        }
    }

    public var publicKey: KEMPublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_kyber_pre_key_record_get_public_key($0, nativeHandle)
                }
            }
        }
    }

    public var secretKey: KEMSecretKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_kyber_pre_key_record_get_secret_key($0, nativeHandle)
                }
            }
        }
    }

    public var signature: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_kyber_pre_key_record_get_signature($0, nativeHandle)
                }
            }
        }
    }
}
