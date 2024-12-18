//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class PreKeyBundle: NativeHandleOwner<SignalMutPointerPreKeyBundle> {
    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerPreKeyBundle>) -> SignalFfiErrorRef? {
        return signal_pre_key_bundle_destroy(handle.pointer)
    }

    // with a prekey
    public convenience init<Bytes: ContiguousBytes>(
        registrationId: UInt32,
        deviceId: UInt32,
        prekeyId: UInt32,
        prekey: PublicKey,
        signedPrekeyId: UInt32,
        signedPrekey: PublicKey,
        signedPrekeySignature: Bytes,
        identity identityKey: IdentityKey
    ) throws {
        var result = SignalMutPointerPreKeyBundle()
        try withNativeHandles(prekey, signedPrekey, identityKey.publicKey) { prekeyHandle, signedPrekeyHandle, identityKeyHandle in
            try signedPrekeySignature.withUnsafeBorrowedBuffer { signedSignatureBuffer in
                try [].withUnsafeBorrowedBuffer { kyberSignatureBuffer in
                    try checkError(signal_pre_key_bundle_new(
                        &result,
                        registrationId,
                        deviceId,
                        prekeyId,
                        prekeyHandle.const(),
                        signedPrekeyId,
                        signedPrekeyHandle.const(),
                        signedSignatureBuffer,
                        identityKeyHandle.const(),
                        ~0,
                        SignalConstPointerKyberPublicKey(),
                        kyberSignatureBuffer
                    ))
                }
            }
        }
        self.init(owned: NonNull(result)!)
    }

    // without a prekey
    public convenience init<Bytes: ContiguousBytes>(
        registrationId: UInt32,
        deviceId: UInt32,
        signedPrekeyId: UInt32,
        signedPrekey: PublicKey,
        signedPrekeySignature: Bytes,
        identity identityKey: IdentityKey
    ) throws {
        var result = SignalMutPointerPreKeyBundle()
        try withNativeHandles(signedPrekey, identityKey.publicKey) { signedPrekeyHandle, identityKeyHandle in
            try signedPrekeySignature.withUnsafeBorrowedBuffer { signedSignatureBuffer in
                try [].withUnsafeBorrowedBuffer { kyberSignatureBuffer in
                    try checkError(signal_pre_key_bundle_new(
                        &result,
                        registrationId,
                        deviceId,
                        ~0,
                        SignalConstPointerPublicKey(),
                        signedPrekeyId,
                        signedPrekeyHandle.const(),
                        signedSignatureBuffer,
                        identityKeyHandle.const(),
                        ~0,
                        SignalConstPointerKyberPublicKey(),
                        kyberSignatureBuffer
                    ))
                }
            }
        }
        self.init(owned: NonNull(result)!)
    }

    // with a prekey and KEM key
    public convenience init<
        ECBytes: ContiguousBytes,
        KEMBytes: ContiguousBytes
    >(
        registrationId: UInt32,
        deviceId: UInt32,
        prekeyId: UInt32,
        prekey: PublicKey,
        signedPrekeyId: UInt32,
        signedPrekey: PublicKey,
        signedPrekeySignature: ECBytes,
        identity identityKey: IdentityKey,
        kyberPrekeyId: UInt32,
        kyberPrekey: KEMPublicKey,
        kyberPrekeySignature: KEMBytes
    ) throws {
        var result = SignalMutPointerPreKeyBundle()
        try withNativeHandles(prekey, signedPrekey, identityKey.publicKey, kyberPrekey) { prekeyHandle, signedPrekeyHandle, identityKeyHandle, kyberKeyHandle in
            try signedPrekeySignature.withUnsafeBorrowedBuffer { ecSignatureBuffer in
                try kyberPrekeySignature.withUnsafeBorrowedBuffer { kyberSignatureBuffer in
                    try checkError(signal_pre_key_bundle_new(
                        &result,
                        registrationId,
                        deviceId,
                        prekeyId,
                        prekeyHandle.const(),
                        signedPrekeyId,
                        signedPrekeyHandle.const(),
                        ecSignatureBuffer,
                        identityKeyHandle.const(),
                        kyberPrekeyId,
                        kyberKeyHandle.const(),
                        kyberSignatureBuffer
                    ))
                }
            }
        }
        self.init(owned: NonNull(result)!)
    }

    // without a prekey but with KEM key
    public convenience init<
        ECBytes: ContiguousBytes,
        KEMBytes: ContiguousBytes
    >(
        registrationId: UInt32,
        deviceId: UInt32,
        signedPrekeyId: UInt32,
        signedPrekey: PublicKey,
        signedPrekeySignature: ECBytes,
        identity identityKey: IdentityKey,
        kyberPrekeyId: UInt32,
        kyberPrekey: KEMPublicKey,
        kyberPrekeySignature: KEMBytes
    ) throws {
        var result = SignalMutPointerPreKeyBundle()
        try withNativeHandles(signedPrekey, identityKey.publicKey, kyberPrekey) { signedPrekeyHandle, identityKeyHandle, kyberKeyHandle in
            try signedPrekeySignature.withUnsafeBorrowedBuffer { ecSignatureBuffer in
                try kyberPrekeySignature.withUnsafeBorrowedBuffer { kyberSignatureBuffer in
                    try checkError(signal_pre_key_bundle_new(
                        &result,
                        registrationId,
                        deviceId,
                        ~0,
                        SignalConstPointerPublicKey(),
                        signedPrekeyId,
                        signedPrekeyHandle.const(),
                        ecSignatureBuffer,
                        identityKeyHandle.const(),
                        kyberPrekeyId,
                        kyberKeyHandle.const(),
                        kyberSignatureBuffer
                    ))
                }
            }
        }
        self.init(owned: NonNull(result)!)
    }

    public var registrationId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_pre_key_bundle_get_registration_id($0, nativeHandle.const())
                }
            }
        }
    }

    public var deviceId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_pre_key_bundle_get_device_id($0, nativeHandle.const())
                }
            }
        }
    }

    public var signedPreKeyId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_pre_key_bundle_get_signed_pre_key_id($0, nativeHandle.const())
                }
            }
        }
    }

    public var preKeyId: UInt32? {
        let prekey_id = withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_pre_key_bundle_get_pre_key_id($0, nativeHandle.const())
                }
            }
        }
        return prekey_id == ~0 ? nil : prekey_id
    }

    public var preKeyPublic: PublicKey? {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningOptionalNativeHandle {
                    signal_pre_key_bundle_get_pre_key_public($0, nativeHandle.const())
                }
            }
        }
    }

    public var identityKey: IdentityKey {
        let pk: PublicKey = withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_pre_key_bundle_get_identity_key($0, nativeHandle.const())
                }
            }
        }
        return IdentityKey(publicKey: pk)
    }

    public var signedPreKeyPublic: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_pre_key_bundle_get_signed_pre_key_public($0, nativeHandle.const())
                }
            }
        }
    }

    public var signedPreKeySignature: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_pre_key_bundle_get_signed_pre_key_signature($0, nativeHandle.const())
                }
            }
        }
    }

    public var kyberPreKeyId: UInt32? {
        let prekey_id = withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_pre_key_bundle_get_kyber_pre_key_id($0, nativeHandle.const())
                }
            }
        }
        return prekey_id == ~0 ? nil : prekey_id
    }

    public var kyberPreKeyPublic: KEMPublicKey? {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningOptionalNativeHandle {
                    signal_pre_key_bundle_get_kyber_pre_key_public($0, nativeHandle.const())
                }
            }
        }
    }

    public var kyberPreKeySignature: [UInt8]? {
        let result: [UInt8] = withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_pre_key_bundle_get_kyber_pre_key_signature($0, nativeHandle.const())
                }
            }
        }
        return result.isEmpty ? nil : result
    }
}

extension SignalMutPointerPreKeyBundle: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerPreKeyBundle

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

extension SignalConstPointerPreKeyBundle: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
