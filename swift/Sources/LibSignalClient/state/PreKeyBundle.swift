//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class PreKeyBundle: NativeHandleOwner<SignalMutPointerPreKeyBundle> {
    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerPreKeyBundle>
    ) -> SignalFfiErrorRef? {
        return signal_pre_key_bundle_destroy(handle.pointer)
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
        let result = try withAllBorrowed(
            prekey,
            signedPrekey,
            identityKey.publicKey,
            kyberPrekey,
            .bytes(signedPrekeySignature),
            .bytes(kyberPrekeySignature)
        ) {
            prekeyHandle,
            signedPrekeyHandle,
            identityKeyHandle,
            kyberKeyHandle,
            ecSignatureBuffer,
            kyberSignatureBuffer in
            try invokeFnReturningValueByPointer(.init()) {
                signal_pre_key_bundle_new(
                    $0,
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
                )
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
        let result = try withAllBorrowed(
            signedPrekey,
            identityKey.publicKey,
            kyberPrekey,
            .bytes(signedPrekeySignature),
            .bytes(kyberPrekeySignature)
        ) { signedPrekeyHandle, identityKeyHandle, kyberKeyHandle, ecSignatureBuffer, kyberSignatureBuffer in
            try invokeFnReturningValueByPointer(.init()) {
                signal_pre_key_bundle_new(
                    $0,
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
                )
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

    public var signedPreKeySignature: Data {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_pre_key_bundle_get_signed_pre_key_signature($0, nativeHandle.const())
                }
            }
        }
    }

    public var kyberPreKeyId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_pre_key_bundle_get_kyber_pre_key_id($0, nativeHandle.const())
                }
            }
        }
    }

    public var kyberPreKeyPublic: KEMPublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_pre_key_bundle_get_kyber_pre_key_public($0, nativeHandle.const())
                }
            }
        }
    }

    public var kyberPreKeySignature: Data {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_pre_key_bundle_get_kyber_pre_key_signature($0, nativeHandle.const())
                }
            }
        }
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
