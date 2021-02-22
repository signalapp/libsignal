//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class Aes256GcmSiv: ClonableHandleOwner {
    public init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_aes256_gcm_siv_new(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
        super.init(owned: handle!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_aes256_gcm_siv_destroy(handle)
    }

    public func encrypt<MessageBytes, NonceBytes, AssociatedDataBytes>(
      _ message: MessageBytes,
      _ nonce: NonceBytes,
      _ associated_data: AssociatedDataBytes) throws -> [UInt8]
      where MessageBytes: ContiguousBytes,
            NonceBytes: ContiguousBytes,
            AssociatedDataBytes: ContiguousBytes {

        try message.withUnsafeBytes { messageBytes in
            try nonce.withUnsafeBytes { nonceBytes in
                try associated_data.withUnsafeBytes { adBytes in
                    try invokeFnReturningArray {
                        signal_aes256_gcm_siv_encrypt($0,
                                                      $1,
                                                      nativeHandle,
                                                      messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                      messageBytes.count,
                                                      nonceBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                      nonceBytes.count,
                                                      adBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                      adBytes.count)
                    }
                }
            }
        }
    }

    public func decrypt<MessageBytes, NonceBytes, AssociatedDataBytes> (
      _ message: MessageBytes,
      _ nonce: NonceBytes,
      _ associated_data: AssociatedDataBytes) throws -> [UInt8]
      where MessageBytes: ContiguousBytes,
            NonceBytes: ContiguousBytes,
            AssociatedDataBytes: ContiguousBytes {

        try message.withUnsafeBytes { messageBytes in
            try nonce.withUnsafeBytes { nonceBytes in
                try associated_data.withUnsafeBytes { adBytes in
                    try invokeFnReturningArray {
                        signal_aes256_gcm_siv_decrypt($0,
                                                      $1,
                                                      nativeHandle,
                                                      messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                      messageBytes.count,
                                                      nonceBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                      nonceBytes.count,
                                                      adBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                      adBytes.count)
                    }
                }
            }
        }
    }

}
