//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class Aes256GcmSiv: NativeHandleOwner<SignalMutPointerAes256GcmSiv> {
    public convenience init<Bytes: ContiguousBytes>(key bytes: Bytes) throws {
        let handle = try bytes.withUnsafeBorrowedBuffer {
            var result = SignalMutPointerAes256GcmSiv()
            try checkError(signal_aes256_gcm_siv_new(&result, $0))
            return result
        }
        self.init(owned: NonNull(handle)!)
    }

    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerAes256GcmSiv>) -> SignalFfiErrorRef? {
        return signal_aes256_gcm_siv_destroy(handle.pointer)
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
                                nativeHandle.const(),
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
                                nativeHandle.const(),
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

extension SignalMutPointerAes256GcmSiv: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerAes256GcmSiv

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

extension SignalConstPointerAes256GcmSiv: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
