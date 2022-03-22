//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class Aes256GcmSiv: NativeHandleOwner {
    public convenience init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(signal_aes256_gcm_siv_new(&result, $0))
            return result
        }
        self.init(owned: handle!)
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

        try withNativeHandle { nativeHandle in
            try message.withUnsafeBorrowedBuffer { messageBuffer in
                try nonce.withUnsafeBorrowedBuffer { nonceBuffer in
                    try associated_data.withUnsafeBorrowedBuffer { adBuffer in
                        try invokeFnReturningArray {
                            signal_aes256_gcm_siv_encrypt($0,
                                                          $1,
                                                          nativeHandle,
                                                          messageBuffer,
                                                          nonceBuffer,
                                                          adBuffer)
                        }
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

        try withNativeHandle { nativeHandle in
            try message.withUnsafeBorrowedBuffer { messageBuffer in
                try nonce.withUnsafeBorrowedBuffer { nonceBuffer in
                    try associated_data.withUnsafeBorrowedBuffer { adBuffer in
                        try invokeFnReturningArray {
                            signal_aes256_gcm_siv_decrypt($0,
                                                          $1,
                                                          nativeHandle,
                                                          messageBuffer,
                                                          nonceBuffer,
                                                          adBuffer)
                        }
                    }
                }
            }
        }
    }

}
