//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// Implements the
/// [AES-256-CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR))
/// stream cipher with a combined 12-byte nonce and initial 4-byte counter.
///
/// CTR mode is built on XOR, so encrypting and decrypting are the same operation.
public class Aes256Ctr32: NativeHandleOwner<SignalMutPointerAes256Ctr32> {
    public static let keyLength: Int = 32
    public static let nonceLength: Int = 16

    /// Initializes the cipher with the given key and combined nonce.
    ///
    /// The first 12 bytes of the nonce are treated as a traditional nonce, while the last four are
    /// treated as the initial counter---the position in the cipher stream to start at.
    public convenience init<KeyBytes, NonceBytes>(
        key: KeyBytes,
        nonce: NonceBytes
    ) throws where KeyBytes: ContiguousBytes, NonceBytes: ContiguousBytes {
        let handle = try key.withUnsafeBorrowedBuffer { keyBuffer in
            try nonce.withUnsafeBytes { nonceBytes in
                guard nonceBytes.count == Self.nonceLength else {
                    throw SignalError.invalidArgument(
                        "nonce must be \(Self.nonceLength) bytes (got \(nonceBytes.count))"
                    )
                }
                // swift-format-ignore
                // (vertical alignment is clearer)
                let initialCounter =
                    (UInt32(nonceBytes[12]) << 24) |
                    (UInt32(nonceBytes[13]) << 16) |
                    (UInt32(nonceBytes[14]) << 8) |
                    UInt32(nonceBytes[15])
                var nonceBufferWithoutCounter = SignalBorrowedBuffer(nonceBytes)
                nonceBufferWithoutCounter.length -= 4
                return try invokeFnReturningValueByPointer(.init()) {
                    signal_aes256_ctr32_new(
                        $0,
                        keyBuffer,
                        nonceBufferWithoutCounter,
                        initialCounter
                    )
                }
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerAes256Ctr32>
    ) -> SignalFfiErrorRef? {
        return signal_aes256_ctr32_destroy(handle.pointer)
    }

    /// Encrypts the plaintext, or decrypts the ciphertext, in `message`, in place, advancing the
    /// state of the cipher.
    public func process(_ message: inout Data) throws {
        try withNativeHandle { nativeHandle in
            try message.withUnsafeMutableBytes { messageBytes in
                try checkError(
                    signal_aes256_ctr32_process(
                        nativeHandle,
                        SignalBorrowedMutableBuffer(messageBytes),
                        0,
                        UInt32(messageBytes.count)
                    )
                )
            }
        }
    }

    /// Encrypts the plaintext, or decrypts the ciphertext, in `message`, in place, using the given
    /// key and nonce.
    ///
    /// This is a convenience for when the entire message fits in memory.
    public static func process<KeyBytes, NonceBytes>(
        _ message: inout Data,
        key: KeyBytes,
        nonce: NonceBytes
    ) throws where KeyBytes: ContiguousBytes, NonceBytes: ContiguousBytes {
        try Aes256Ctr32(key: key, nonce: nonce).process(&message)
    }
}

extension SignalMutPointerAes256Ctr32: SignalMutPointer {
    public typealias ConstPointer = OpaquePointer?

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        nil
    }
}
