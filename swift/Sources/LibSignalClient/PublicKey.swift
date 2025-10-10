//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class PublicKey: ClonableHandleOwner<SignalMutPointerPublicKey>, @unchecked Sendable {
    public convenience init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle = try bytes.withUnsafeBorrowedBuffer { bytes in
            try invokeFnReturningValueByPointer(.init()) {
                signal_publickey_deserialize($0, bytes)
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerPublicKey>) -> SignalFfiErrorRef?
    {
        return signal_publickey_destroy(handle.pointer)
    }

    override internal class func cloneNativeHandle(
        _ newHandle: inout SignalMutPointerPublicKey,
        currentHandle: SignalConstPointerPublicKey
    ) -> SignalFfiErrorRef? {
        return signal_publickey_clone(&newHandle, currentHandle)
    }

    public var keyBytes: Data {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_publickey_get_public_key_bytes($0, nativeHandle.const())
                }
            }
        }
    }

    public func serialize() -> Data {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_publickey_serialize($0, nativeHandle.const())
                }
            }
        }
    }

    public func verifySignature(message: some ContiguousBytes, signature: some ContiguousBytes) throws -> Bool {
        return try withAllBorrowed(self, .bytes(message), .bytes(signature)) {
            nativeHandle,
            messageBuffer,
            signatureBuffer in
            try invokeFnReturningBool {
                signal_publickey_verify($0, nativeHandle.const(), messageBuffer, signatureBuffer)
            }
        }
    }

    /// Seals a message so only the holder of the private key can decrypt it.
    ///
    /// Uses HPKE ([RFC 9180][]). The output will include a type byte indicating the chosen
    /// algorithms and ciphertext layout. The `info` parameter should typically be a static value
    /// describing the purpose of the message, while `associatedData` can be used to restrict
    /// successful decryption beyond holding the private key.
    ///
    /// - SeeAlso ``PrivateKey/open(_:info:associatedData:)-(_,ContiguousBytes,_)``
    ///
    /// [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html
    public func seal(
        _ message: some ContiguousBytes,
        info: some ContiguousBytes,
        associatedData: some ContiguousBytes = []
    ) -> Data {
        failOnError {
            try withAllBorrowed(self, .bytes(message), .bytes(info), .bytes(associatedData)) {
                nativeHandle,
                messageBuffer,
                infoBuffer,
                aadBuffer in
                try invokeFnReturningData {
                    signal_publickey_hpke_seal($0, nativeHandle.const(), messageBuffer, infoBuffer, aadBuffer)
                }
            }
        }
    }

    /// Convenience overload for ``seal(_:info:associatedData:)-(_,ContiguousBytes,_)``, using the UTF-8 bytes of `info`.
    public func seal(
        _ message: some ContiguousBytes,
        info: String,
        associatedData: some ContiguousBytes = []
    ) -> Data {
        var info = info
        return info.withUTF8 {
            seal(message, info: $0, associatedData: associatedData)
        }
    }

    public func compare(_ other: PublicKey) -> Int32 {
        return failOnError {
            try withAllBorrowed(self, other) { selfHandle, otherHandle in
                try invokeFnReturningInteger {
                    signal_publickey_compare($0, selfHandle.const(), otherHandle.const())
                }
            }
        }
    }
}

extension PublicKey: Equatable {
    public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.compare(rhs) == 0
    }
}

extension PublicKey: Comparable {
    public static func < (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.compare(rhs) < 0
    }
}

extension SignalMutPointerPublicKey: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerPublicKey

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> SignalConstPointerPublicKey {
        return SignalConstPointerPublicKey(raw: self.raw)
    }
}

extension SignalConstPointerPublicKey: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
