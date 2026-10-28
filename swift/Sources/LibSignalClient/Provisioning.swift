//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// The state that a secondary device keeps while it is waiting to receive an encrypted `ProvisionMessage` or
/// `RegistrationProvisionMessage` from the primary.
public class RecvProvisionCiphertextState: NativeHandleOwner<SignalMutPointerRecvProvisionCiphertextState>,
    @unchecked Sendable
{
    /// Generates a new state with a fresh, random keypair.
    public static func generate() -> RecvProvisionCiphertextState {
        failOnError {
            try NativeNice.RecvProvisionCiphertextState_Generate()
        }
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerRecvProvisionCiphertextState>
    ) -> SignalFfiErrorRef? {
        return signal_recv_provision_ciphertext_state_destroy(handle.pointer)
    }

    /// The 33-byte serialized public key that the primary should encrypt to. This is what the secondary puts in its
    /// provisioning QR code.
    public var publicKey: Data {
        failOnError {
            try NativeNice.RecvProvisionCiphertextState_GetPublicKey(state: self)
        }
    }

    /// Decrypts a serialized `ProvisionEnvelope` and returns the underlying serialized `ProvisionMessage` or
    /// `RegistrationProvisionMessage`.
    ///
    /// - Throws: ``SignalError/invalidMessage(_:)`` if the envelope is malformed, was not encrypted to this state's
    ///   public key, or has been tampered with.
    public func decryptEnvelope<Bytes: ContiguousBytes>(_ envelope: Bytes) throws -> Data {
        try NativeNice.RecvProvisionCiphertextState_DecryptEnvelope(
            state: self,
            envelope: envelope.withUnsafeBytes { Data($0) }
        )
    }
}

/// Encrypts a serialized `ProvisionMessage` or `RegistrationProvisionMessage` to a secondary device, returning a
/// serialized `ProvisionEnvelope`.
///
/// - Parameter secondaryPublicKey: The 33-byte public key from the secondary's provisioning QR code, i.e.
///   ``RecvProvisionCiphertextState/publicKey``.
/// - Throws: ``SignalError/invalidType(_:)`` if `secondaryPublicKey` is not 33 bytes, or
///   ``SignalError/invalidMessage(_:)`` if its first byte is not the X25519 key type byte (0x05).
public func encryptProvisionMessage<KeyBytes: ContiguousBytes, MessageBytes: ContiguousBytes>(
    secondaryPublicKey: KeyBytes,
    provisionMessage: MessageBytes
) throws -> Data {
    // Check the length here, since NativeNice treats a wrong-length key as a programmer error and crashes
    let secondaryPublicKey = secondaryPublicKey.withUnsafeBytes { Data($0) }
    guard secondaryPublicKey.count == 33 else {
        throw SignalError.invalidType("secondaryPublicKey must be 33 bytes, but was \(secondaryPublicKey.count) bytes")
    }
    return try NativeNice.Provisioning_EncryptProvisionMessage(
        secondaryPublicKey: secondaryPublicKey,
        provisionMessage: provisionMessage.withUnsafeBytes { Data($0) }
    )
}

extension SignalMutPointerRecvProvisionCiphertextState: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerRecvProvisionCiphertextState

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

extension SignalConstPointerRecvProvisionCiphertextState: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
