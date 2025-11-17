//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// Implements the [AES-256-GCM-SIV](https://en.wikipedia.org/wiki/AES-GCM-SIV)
/// authenticated stream cipher with a 12-byte nonce.
///
/// AES-GCM-SIV is a multi-pass algorithm (to generate the "synthetic initialization vector"), so
/// this API does not expose a streaming form.
public class Aes256GcmSiv: NativeHandleOwner<SignalMutPointerAes256GcmSiv> {
    public convenience init<Bytes: ContiguousBytes>(key bytes: Bytes) throws {
        let handle = try bytes.withUnsafeBorrowedBuffer { bytes in
            try invokeFnReturningValueByPointer(.init()) {
                signal_aes256_gcm_siv_new($0, bytes)
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerAes256GcmSiv>
    ) -> SignalFfiErrorRef? {
        return signal_aes256_gcm_siv_destroy(handle.pointer)
    }

    /// Encrypts the given plaintext using the given nonce, and authenticating the ciphertext and given
    /// associated data.
    ///
    /// The associated data is not included in the ciphertext; instead, it's expected to match between
    /// the encrypter and decrypter. If you don't need any extra data, pass an empty array.
    ///
    /// - Returns: The encrypted data, including an appended 16-byte authentication tag.
    public func encrypt(
        _ message: some ContiguousBytes,
        nonce: some ContiguousBytes,
        associatedData: some ContiguousBytes
    ) throws -> Data {
        try withNativeHandle { nativeHandle in
            try message.withUnsafeBorrowedBuffer { messageBuffer in
                try nonce.withUnsafeBorrowedBuffer { nonceBuffer in
                    try associatedData.withUnsafeBorrowedBuffer { adBuffer in
                        try invokeFnReturningData {
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

    /// Decrypts the given ciphertext using the given nonce, and authenticating the ciphertext and
    /// given associated data.
    ///
    /// The associated data is not included in the ciphertext; instead, it's expected to match
    /// between the encrypter and decrypter.
    ///
    /// - Returns: The decrypted data
    public func decrypt(
        _ message: some ContiguousBytes,
        nonce: some ContiguousBytes,
        associatedData: some ContiguousBytes
    ) throws -> Data {
        try withNativeHandle { nativeHandle in
            try message.withUnsafeBorrowedBuffer { messageBuffer in
                try nonce.withUnsafeBorrowedBuffer { nonceBuffer in
                    try associatedData.withUnsafeBorrowedBuffer { adBuffer in
                        try invokeFnReturningData {
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
