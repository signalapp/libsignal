//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class Aes256GcmSiv: NativeHandleOwner {
    public convenience init<Bytes: ContiguousBytes>(key bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(signal_aes256_gcm_siv_new(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_aes256_gcm_siv_destroy(handle)
    }

    public func encrypt(
        _ message: some ContiguousBytes,
        nonce: some ContiguousBytes,
        associatedData: some ContiguousBytes
    ) throws -> [UInt8] {
        try withNativeHandle { nativeHandle in
            try message.withUnsafeBorrowedBuffer { messageBuffer in
                try nonce.withUnsafeBorrowedBuffer { nonceBuffer in
                    try associatedData.withUnsafeBorrowedBuffer { adBuffer in
                        try invokeFnReturningArray {
                            signal_aes256_gcm_siv_encrypt(
                                $0,
                                nativeHandle,
                                messageBuffer,
                                nonceBuffer,
                                adBuffer
                            )
                        }
                    }
                }
            }
        }
    }

    public func decrypt(
        _ message: some ContiguousBytes,
        nonce: some ContiguousBytes,
        associatedData: some ContiguousBytes
    ) throws -> [UInt8] {
        try withNativeHandle { nativeHandle in
            try message.withUnsafeBorrowedBuffer { messageBuffer in
                try nonce.withUnsafeBorrowedBuffer { nonceBuffer in
                    try associatedData.withUnsafeBorrowedBuffer { adBuffer in
                        try invokeFnReturningArray {
                            signal_aes256_gcm_siv_decrypt(
                                $0,
                                nativeHandle,
                                messageBuffer,
                                nonceBuffer,
                                adBuffer
                            )
                        }
                    }
                }
            }
        }
    }
}
