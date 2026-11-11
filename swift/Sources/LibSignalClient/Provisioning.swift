//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// The public key that a secondary device puts in its provisioning QR code, and that the primary encrypts the
/// `ProvisionMessage` or `RegistrationProvisionMessage` to.
public class ProvisioningPublicKey: NativeHandleOwner<SignalMutPointerProvisioningPublicKey>, @unchecked Sendable {
    /// Wraps a serialized public key, i.e. the output of ``serialize()``. The public key is not validated until it is
    /// used.
    public convenience init<Bytes: ContiguousBytes>(_ pubkeyBytes: Bytes) {
        let handle = failOnError {
            try pubkeyBytes.withUnsafeBorrowedBuffer { pubkeyBytes in
                try invokeFnReturningValueByPointer(.init()) {
                    signal_provisioning_public_key_deserialize($0, pubkeyBytes)
                }
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerProvisioningPublicKey>
    ) -> SignalFfiErrorRef? {
        return signal_provisioning_public_key_destroy(handle.pointer)
    }

    /// Returns the bytes this public key was created from.
    public func serialize() -> Data {
        failOnError {
            try NativeNice.ProvisioningPublicKey_Serialize(key: self)
        }
    }
}

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

    /// The public key that the primary should encrypt to. This is what the secondary puts in its provisioning QR code.
    public var publicKey: ProvisioningPublicKey {
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
/// - Parameter secondaryPublicKey: The public key from the secondary's provisioning QR code, i.e.
///   ``RecvProvisionCiphertextState/publicKey``.
/// - Throws: ``SignalError/invalidKey(_:)`` if `secondaryPublicKey` is malformed.
public func encryptProvisionMessage<MessageBytes: ContiguousBytes>(
    secondaryPublicKey: ProvisioningPublicKey,
    provisionMessage: MessageBytes
) throws -> Data {
    try NativeNice.Provisioning_EncryptProvisionMessage(
        secondaryPublicKey: secondaryPublicKey,
        provisionMessage: provisionMessage.withUnsafeBytes { Data($0) }
    )
}

extension SignalMutPointerProvisioningPublicKey: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerProvisioningPublicKey

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

extension SignalConstPointerProvisioningPublicKey: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
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
