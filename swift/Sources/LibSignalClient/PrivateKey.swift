//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class PrivateKey: ClonableHandleOwner<SignalMutPointerPrivateKey>, @unchecked Sendable {
    public convenience init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle = try bytes.withUnsafeBorrowedBuffer { bytes in
            try invokeFnReturningValueByPointer(.init()) {
                signal_privatekey_deserialize($0, bytes)
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    public static func generate() -> PrivateKey {
        return failOnError {
            try invokeFnReturningNativeHandle {
                signal_privatekey_generate($0)
            }
        }
    }

    override internal class func cloneNativeHandle(
        _ newHandle: inout SignalMutPointerPrivateKey,
        currentHandle: SignalConstPointerPrivateKey
    ) -> SignalFfiErrorRef? {
        return signal_privatekey_clone(&newHandle, currentHandle)
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerPrivateKey>
    ) -> SignalFfiErrorRef? {
        return signal_privatekey_destroy(handle.pointer)
    }

    public func serialize() -> Data {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_privatekey_serialize($0, nativeHandle.const())
                }
            }
        }
    }

    public func generateSignature<Bytes: ContiguousBytes>(message: Bytes) -> Data {
        return withNativeHandle { nativeHandle in
            message.withUnsafeBorrowedBuffer { messageBuffer in
                failOnError {
                    try invokeFnReturningData {
                        signal_privatekey_sign($0, nativeHandle.const(), messageBuffer)
                    }
                }
            }
        }
    }

    public func keyAgreement(with other: PublicKey) -> Data {
        return failOnError {
            try withAllBorrowed(self, other) { nativeHandle, otherHandle in
                try invokeFnReturningData {
                    signal_privatekey_agree($0, nativeHandle.const(), otherHandle.const())
                }
            }
        }
    }

    /// Opens a ciphertext sealed with ``PublicKey/seal(_:info:associatedData:)-(_,ContiguousBytes,_)``.
    ///
    /// Uses HPKE ([RFC 9180][]). The input should include its original type byte indicating the
    /// chosen algorithms and ciphertext layout. The `info` and `associatedData` must match those
    /// used during sealing.
    ///
    /// [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html
    public func open(
        _ ciphertext: some ContiguousBytes,
        info: some ContiguousBytes,
        associatedData: some ContiguousBytes = []
    ) throws -> Data {
        try withAllBorrowed(self, .bytes(ciphertext), .bytes(info), .bytes(associatedData)) {
            nativeHandle,
            ciphertextBuffer,
            infoBuffer,
            aadBuffer in
            try invokeFnReturningData {
                signal_privatekey_hpke_open($0, nativeHandle.const(), ciphertextBuffer, infoBuffer, aadBuffer)
            }
        }
    }

    /// Convenience overload for ``open(_:info:associatedData:)-(_,ContiguousBytes,_)``, using the UTF-8 bytes of `info`.
    public func open(
        _ ciphertext: some ContiguousBytes,
        info: String,
        associatedData: some ContiguousBytes = []
    ) throws -> Data {
        var info = info
        return try info.withUTF8 {
            try open(ciphertext, info: $0, associatedData: associatedData)
        }
    }

    public var publicKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_privatekey_get_public_key($0, nativeHandle.const())
                }
            }
        }
    }
}

extension SignalMutPointerPrivateKey: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerPrivateKey

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> SignalConstPointerPrivateKey {
        SignalConstPointerPrivateKey(raw: self.raw)
    }
}

extension SignalConstPointerPrivateKey: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
