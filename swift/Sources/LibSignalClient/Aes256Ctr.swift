//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class Aes256Ctr32: NativeHandleOwner {
    public static let keyLength: Int = 32
    public static let nonceLength: Int = 16

    public convenience init<KeyBytes, NonceBytes>(
        key: KeyBytes,
        nonce: NonceBytes
    ) throws where KeyBytes: ContiguousBytes, NonceBytes: ContiguousBytes {
        let handle: OpaquePointer? = try key.withUnsafeBorrowedBuffer { keyBuffer in
            try nonce.withUnsafeBytes { nonceBytes in
                guard nonceBytes.count == Self.nonceLength else {
                    throw SignalError.invalidArgument("nonce must be \(Self.nonceLength) bytes (got \(nonceBytes.count))")
                }
                let initialCounter =
                    (UInt32(nonceBytes[12]) << 24) |
                    (UInt32(nonceBytes[13]) << 16) |
                    (UInt32(nonceBytes[14]) << 8) |
                    UInt32(nonceBytes[15])
                var nonceBufferWithoutCounter = SignalBorrowedBuffer(nonceBytes)
                nonceBufferWithoutCounter.length -= 4
                var result: OpaquePointer?
                try checkError(signal_aes256_ctr32_new(
                    &result,
                    keyBuffer,
                    nonceBufferWithoutCounter,
                    initialCounter
                ))
                return result
            }
        }
        self.init(owned: handle!)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_aes256_ctr32_destroy(handle)
    }

    public func process(_ message: inout Data) throws {
        try withNativeHandle { nativeHandle in
            try message.withUnsafeMutableBytes { messageBytes in
                try checkError(signal_aes256_ctr32_process(
                    nativeHandle,
                    SignalBorrowedMutableBuffer(messageBytes),
                    0,
                    UInt32(messageBytes.count)
                ))
            }
        }
    }

    public static func process<KeyBytes, NonceBytes>(
        _ message: inout Data,
        key: KeyBytes,
        nonce: NonceBytes
    ) throws where KeyBytes: ContiguousBytes, NonceBytes: ContiguousBytes {
        try Aes256Ctr32(key: key, nonce: nonce).process(&message)
    }
}
