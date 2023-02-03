//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public struct Aes256GcmEncryptedData {
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

    @inlinable
    public init(concatenated: Data) throws {
        guard concatenated.count >= Self.nonceLength + Self.authenticationTagLength else {
            throw SignalError.invalidMessage("concatenated AES-256-GCM ciphertext too short")
        }
        self.nonce = concatenated.prefix(Self.nonceLength)
        self.ciphertext = concatenated.dropFirst(Self.nonceLength).dropLast(Self.authenticationTagLength)
        self.authenticationTag = concatenated.suffix(Self.authenticationTagLength)
    }

    public func concatenate() -> Data {
        var result = Data(capacity: nonce.count + ciphertext.count + authenticationTag.count)
        result += nonce
        result += ciphertext
        result += authenticationTag
        return result
    }

    public static func encrypt<KeyBytes, AssociatedDataBytes>(
        _ message: Data,
        key: KeyBytes,
        associatedData: AssociatedDataBytes
    ) throws -> Self
    where KeyBytes: ContiguousBytes, AssociatedDataBytes: ContiguousBytes {
        var nonce = Data(count: Self.nonceLength)
        try nonce.withUnsafeMutableBytes { try fillRandom($0) }

        let cipher = try Aes256GcmEncryption(key: key, nonce: nonce, associatedData: associatedData)
        var ciphertext = message
        try cipher.encrypt(&ciphertext)
        let tag = try cipher.computeTag()
        assert(tag.count == Self.authenticationTagLength)
        return Self(nonce: nonce, ciphertext: ciphertext, authenticationTag: tag)
    }

    public static func encrypt<KeyBytes: ContiguousBytes>(_ message: Data, key: KeyBytes) throws -> Self {
        return try encrypt(message, key: key, associatedData: [])
    }

    // Inlinable here specifically to avoid copying the ciphertext again if the struct is no longer used.
    @inlinable
    public func decrypt<KeyBytes, AssociatedDataBytes>(
        key: KeyBytes,
        associatedData: AssociatedDataBytes
    ) throws -> Data
    where KeyBytes: ContiguousBytes, AssociatedDataBytes: ContiguousBytes {
        let cipher = try Aes256GcmDecryption(key: key, nonce: self.nonce, associatedData: associatedData)
        var plaintext = self.ciphertext
        try cipher.decrypt(&plaintext)
        guard try cipher.verifyTag(self.authenticationTag) else {
            throw SignalError.invalidMessage("failed to decrypt")
        }
        return plaintext
    }

    @inlinable
    public func decrypt<KeyBytes: ContiguousBytes>(key: KeyBytes) throws -> Data {
        return try decrypt(key: key, associatedData: [])
    }
}

/// Supports streamed encryption and custom nonces. Use Aes256GcmEncryptedData if you don't need either.
public class Aes256GcmEncryption: NativeHandleOwner {
    public convenience init<KeyBytes, NonceBytes, AssociatedDataBytes>(
        key: KeyBytes,
        nonce: NonceBytes,
        associatedData: AssociatedDataBytes
    ) throws where KeyBytes: ContiguousBytes, NonceBytes: ContiguousBytes, AssociatedDataBytes: ContiguousBytes {
        let handle: OpaquePointer? = try key.withUnsafeBorrowedBuffer { keyBuffer in
            try nonce.withUnsafeBorrowedBuffer { nonceBuffer in
                try associatedData.withUnsafeBorrowedBuffer { adBuffer in
                    var result: OpaquePointer?
                    try checkError(signal_aes256_gcm_encryption_new(&result,
                                                                    keyBuffer,
                                                                    nonceBuffer,
                                                                    adBuffer))
                    return result
                }
            }
        }
        self.init(owned: handle!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_aes256_gcm_encryption_destroy(handle)
    }

    public func encrypt(_ message: inout Data) throws {
        try withNativeHandle { nativeHandle in
            try message.withUnsafeMutableBytes { messageBytes in
                try checkError(signal_aes256_gcm_encryption_update(nativeHandle,
                                                                   SignalBorrowedMutableBuffer(messageBytes),
                                                                   0,
                                                                   UInt32(messageBytes.count)))
            }
        }
    }

    public func computeTag() throws -> Data {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningData {
                signal_aes256_gcm_encryption_compute_tag($0, nativeHandle)
            }
        }
    }
}

/// Supports streamed decryption. Use Aes256GcmEncryptedData if you don't need streamed decryption.
public class Aes256GcmDecryption: NativeHandleOwner {
    public convenience init<KeyBytes, NonceBytes, AssociatedDataBytes>(
        key: KeyBytes,
        nonce: NonceBytes,
        associatedData: AssociatedDataBytes
    ) throws where KeyBytes: ContiguousBytes, NonceBytes: ContiguousBytes, AssociatedDataBytes: ContiguousBytes {
        let handle: OpaquePointer? = try key.withUnsafeBorrowedBuffer { keyBuffer in
            try nonce.withUnsafeBorrowedBuffer { nonceBuffer in
                try associatedData.withUnsafeBorrowedBuffer { adBuffer in
                    var result: OpaquePointer?
                    try checkError(signal_aes256_gcm_decryption_new(&result,
                                                                    keyBuffer,
                                                                    nonceBuffer,
                                                                    adBuffer))
                    return result
                }
            }
        }
        self.init(owned: handle!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_aes256_gcm_decryption_destroy(handle)
    }

    public func decrypt(_ message: inout Data) throws {
        try withNativeHandle { nativeHandle in
            try message.withUnsafeMutableBytes { messageBytes in
                try checkError(signal_aes256_gcm_decryption_update(nativeHandle,
                                                                   SignalBorrowedMutableBuffer(messageBytes),
                                                                   0,
                                                                   UInt32(messageBytes.count)))
            }
        }
    }

    public func verifyTag<Bytes: ContiguousBytes>(_ tag: Bytes) throws -> Bool {
        return try withNativeHandle { nativeHandle in
            try tag.withUnsafeBorrowedBuffer { tagBuffer in
                var result = false
                try checkError(signal_aes256_gcm_decryption_verify_tag(&result,
                                                                       nativeHandle,
                                                                       tagBuffer))
                return result
            }
        }
    }
}
