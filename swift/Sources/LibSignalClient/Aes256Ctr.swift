//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class Aes256Ctr32: NativeHandleOwner<SignalMutPointerAes256Ctr32> {
    public static let keyLength: Int = 32
    public static let nonceLength: Int = 16

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
