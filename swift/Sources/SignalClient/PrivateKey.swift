//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class PrivateKey: ClonableHandleOwner {
    public init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_privatekey_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
        super.init(owned: handle!)
    }

    internal override init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    public static func generate() -> PrivateKey {
        var handle: OpaquePointer?
        failOnError(signal_privatekey_generate(&handle))
        return PrivateKey(owned: handle!)
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_privatekey_clone(&newHandle, currentHandle)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_privatekey_destroy(handle)
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_privatekey_serialize(nativeHandle, $0, $1)
            }
        }
    }

    public func generateSignature<Bytes: ContiguousBytes>(message: Bytes) -> [UInt8] {
        return message.withUnsafeBytes { messageBytes in
            failOnError {
                try invokeFnReturningArray {
                    signal_privatekey_sign($0, $1, nativeHandle, messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), messageBytes.count)
                }
            }
        }
    }

    public func keyAgreement(with other: PublicKey) -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_privatekey_agree($0, $1, nativeHandle, other.nativeHandle)
            }
        }
    }

    public var publicKey: PublicKey {
        return failOnError {
            try invokeFnReturningPublicKey {
                signal_privatekey_get_public_key($0, nativeHandle)
            }
        }
    }

}
