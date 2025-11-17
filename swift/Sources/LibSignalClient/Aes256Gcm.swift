//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// Provides convenient use of the
/// [AES-256-GCM](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Galois/counter_(GCM))
/// authenticated stream cipher with a 12-byte nonce.
///
/// This struct packs up all the data needed to transmit an AES-GCM ciphertext, and makes it easy to
/// operate on a full ciphertext at once. If you need streaming encryption or decryption, you can
/// use the more manual APIs ``Aes256GcmEncryption`` and ``Aes256GcmDecryption``.
public struct Aes256GcmEncryptedData: Sendable {
    public static let keyLength: Int = 32
    public static let nonceLength: Int = 12
    public static let authenticationTagLength: Int = 16

    public let nonce: Data
    public let ciphertext: Data
    public let authenticationTag: Data

    @inlinable
    public init(nonce: Data, ciphertext: Data, authenticationTag: Data) {
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.authenticationTag = authenticationTag
    }

    /// Assumes `concatenated` is the concatenation `nonce || ciphertext || authenticationTag`, and
    /// splits it up accordingly.
    ///
    /// Throws if the data is too short to contain all three parts (though technically the
    /// ciphertext may be empty).
    @inlinable
    public init(concatenated: Data) throws {
        guard concatenated.count >= Self.nonceLength + Self.authenticationTagLength else {
            throw SignalError.invalidMessage("concatenated AES-256-GCM ciphertext too short")
        }
        self.nonce = concatenated.prefix(Self.nonceLength)
        self.ciphertext = concatenated.dropFirst(Self.nonceLength).dropLast(Self.authenticationTagLength)
        self.authenticationTag = concatenated.suffix(Self.authenticationTagLength)
    }

    /// Concatenates the nonce, ciphertext, and authentication tag, in that order.
    ///
    /// This is a fairly standard way to send AES-GCM ciphertexts. The result is suitable for
    /// passing to ``init(concatenated:)``.
    public func concatenate() -> Data {
        var result = Data(capacity: nonce.count + self.ciphertext.count + self.authenticationTag.count)
        result += self.nonce
        result += self.ciphertext
        result += self.authenticationTag
        return result
    }

    /// Encrypts the given plaintext using the given key, and authenticating the ciphertext and
    /// given associated data.
    ///
    /// The associated data is not included in the ciphertext; instead, it's expected to match
    /// between the encrypter and decrypter. If you don't need any extra data, use the other
    /// overload ``encrypt(_:key:)``.
    ///
    /// This API will generate a random nonce, which is included in the result.
    public static func encrypt(
        _ message: Data,
        key: some ContiguousBytes,
        associatedData: some ContiguousBytes
    ) throws -> Self {
        var nonce = Data(count: Self.nonceLength)
        try nonce.withUnsafeMutableBytes { try fillRandom($0) }

        let cipher = try Aes256GcmEncryption(key: key, nonce: nonce, associatedData: associatedData)
        var ciphertext = message
        try cipher.encrypt(&ciphertext)
        let tag = try cipher.computeTag()
        assert(tag.count == Self.authenticationTagLength)
        return Self(nonce: nonce, ciphertext: ciphertext, authenticationTag: tag)
    }

    /// Encrypts the given plaintext using the given key, authenticating the ciphertext.
    ///
    /// This API will generate a random nonce, which is included in the result.
    ///
    /// - SeeAlso: ``encrypt(_:key:associatedData:)``
    public static func encrypt(_ message: Data, key: some ContiguousBytes) throws -> Self {
        return try self.encrypt(message, key: key, associatedData: [])
    }

    /// Decrypts `self` using the given key, and authenticates the ciphertext and given associated
    /// data.
    ///
    /// The associated data is not included in the ciphertext; instead, it's expected to match
    /// between the encrypter and decrypter. If you don't have any extra data, use the other
    /// overload ``decrypt(key:)``.
    @inlinable  // Inlinable here specifically to avoid copying the ciphertext again if the struct is no longer used.
    public func decrypt(
        key: some ContiguousBytes,
        associatedData: some ContiguousBytes
    ) throws -> Data {
        let cipher = try Aes256GcmDecryption(key: key, nonce: self.nonce, associatedData: associatedData)
        var plaintext = self.ciphertext
        try cipher.decrypt(&plaintext)
        guard try cipher.verifyTag(self.authenticationTag) else {
            throw SignalError.invalidMessage("failed to decrypt")
        }
        return plaintext
    }

    /// Decrypts `self` using the given key, authenticating the ciphertext.
    ///
    /// - SeeAlso: ``decrypt(key:associatedData:)``
    @inlinable
    public func decrypt(key: some ContiguousBytes) throws -> Data {
        return try self.decrypt(key: key, associatedData: [])
    }
}

/// Implements the
/// [AES-256-GCM](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Galois/counter_(GCM))
/// authenticated stream cipher with a 12-byte nonce.
///
/// This API exposes the streaming nature of AES-GCM to allow decrypting data without having it
/// resident in memory all at once. You must call ``computeTag()`` when the encryption is complete,
/// or else you have no authenticity guarantees. Use ``Aes256GcmEncryptedData`` instead if you don't
/// need to stream the data or choose your own nonce.
///
/// - SeeAlso: ``Aes256GcmDecryption``
public class Aes256GcmEncryption: NativeHandleOwner<SignalMutPointerAes256GcmEncryption> {
    /// Initializes the cipher with the given inputs.
    ///
    /// The associated data is not included in the plaintext or tag; instead, it's expected to match
    /// between the encrypter and decrypter. If you don't need any extra data, pass an empty array.
    public convenience init(
        key: some ContiguousBytes,
        nonce: some ContiguousBytes,
        associatedData: some ContiguousBytes
    ) throws {
        let handle = try key.withUnsafeBorrowedBuffer { keyBuffer in
            try nonce.withUnsafeBorrowedBuffer { nonceBuffer in
                try associatedData.withUnsafeBorrowedBuffer { adBuffer in
                    try invokeFnReturningValueByPointer(.init()) {
                        signal_aes256_gcm_encryption_new(
                            $0,
                            keyBuffer,
                            nonceBuffer,
                            adBuffer
                        )
                    }
                }
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerAes256GcmEncryption>
    ) -> SignalFfiErrorRef? {
        return signal_aes256_gcm_encryption_destroy(handle.pointer)
    }

    /// Encrypts `message` in place and advances the state of the cipher.
    ///
    /// Don't forget to call ``computeTag()`` when encryption is complete.
    public func encrypt(_ message: inout Data) throws {
        try withNativeHandle { nativeHandle in
            try message.withUnsafeMutableBytes { messageBytes in
                try checkError(
                    signal_aes256_gcm_encryption_update(
                        nativeHandle,
                        SignalBorrowedMutableBuffer(messageBytes),
                        0,
                        UInt32(messageBytes.count)
                    )
                )
            }
        }
    }

    /// Produces an authentication tag for the plaintext that has been processed.
    ///
    /// After calling `computeTag()`, this object may not be used anymore.
    public func computeTag() throws -> Data {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningData {
                signal_aes256_gcm_encryption_compute_tag($0, nativeHandle)
            }
        }
    }
}

extension SignalMutPointerAes256GcmEncryption: SignalMutPointer {
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

/// Implements the
/// [AES-256-GCM](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Galois/counter_(GCM))
/// authenticated stream cipher with a 12-byte nonce.
///
/// This API exposes the streaming nature of AES-GCM to allow decrypting data without having it
/// resident in memory all at once. You **must** call ``verifyTag(_:)`` when the decryption is
/// complete, or else you have no authenticity guarantees. Use ``Aes256GcmEncryptedData`` instead if
/// you don't need streamed decryption.
///
/// - SeeAlso: ``Aes256GcmEncryption``
public class Aes256GcmDecryption: NativeHandleOwner<SignalMutPointerAes256GcmDecryption> {
    /// Initializes the cipher with the given inputs.
    ///
    /// The associated data is not included in the plaintext or tag; instead, it's expected to match
    /// between the encrypter and decrypter.
    public convenience init(
        key: some ContiguousBytes,
        nonce: some ContiguousBytes,
        associatedData: some ContiguousBytes
    ) throws {
        let handle = try key.withUnsafeBorrowedBuffer { keyBuffer in
            try nonce.withUnsafeBorrowedBuffer { nonceBuffer in
                try associatedData.withUnsafeBorrowedBuffer { adBuffer in
                    try invokeFnReturningValueByPointer(.init()) {
                        signal_aes256_gcm_decryption_new(
                            $0,
                            keyBuffer,
                            nonceBuffer,
                            adBuffer
                        )
                    }
                }
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerAes256GcmDecryption>
    ) -> SignalFfiErrorRef? {
        return signal_aes256_gcm_decryption_destroy(handle.pointer)
    }

    /// Decrypts `message` in place and advances the state of the cipher.
    ///
    /// Don't forget to call ``verifyTag(_:)`` when decryption is complete.
    public func decrypt(_ message: inout Data) throws {
        try withNativeHandle { nativeHandle in
            try message.withUnsafeMutableBytes { messageBytes in
                try checkError(
                    signal_aes256_gcm_decryption_update(
                        nativeHandle,
                        SignalBorrowedMutableBuffer(messageBytes),
                        0,
                        UInt32(messageBytes.count)
                    )
                )
            }
        }
    }

    /// Returns `true` if and only if `tag` matches the ciphertext that has been processed.
    ///
    /// Throws if the tag is not structurally valid (which it's acceptable to treat as "did not
    /// return `true`").
    ///
    /// After calling `verifyTag(_:)`, this object may not be used anymore.
    public func verifyTag(_ tag: some ContiguousBytes) throws -> Bool {
        return try withNativeHandle { nativeHandle in
            try tag.withUnsafeBorrowedBuffer { tagBuffer in
                try invokeFnReturningBool {
                    signal_aes256_gcm_decryption_verify_tag($0, nativeHandle, tagBuffer)
                }
            }
        }
    }
}

extension SignalMutPointerAes256GcmDecryption: SignalMutPointer {
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
