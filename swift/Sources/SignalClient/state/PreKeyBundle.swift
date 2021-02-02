//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class PreKeyBundle {
    private var handle: OpaquePointer?

    deinit {
        failOnError(signal_pre_key_bundle_destroy(handle))
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }

    // with a prekey
    public init<Bytes: ContiguousBytes>(registrationId: UInt32,
                                        deviceId: UInt32,
                                        prekeyId: UInt32,
                                        prekey: PublicKey,
                                        signedPrekeyId: UInt32,
                                        signedPrekey: PublicKey,
                                        signedPrekeySignature: Bytes,
                                        identity identityKey: IdentityKey) throws {
        handle = try signedPrekeySignature.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_pre_key_bundle_new(&result,
                                                     registrationId,
                                                     deviceId,
                                                     prekeyId,
                                                     prekey.nativeHandle,
                                                     signedPrekeyId,
                                                     signedPrekey.nativeHandle,
                                                     $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                     $0.count,
                                                     identityKey.publicKey.nativeHandle))
            return result
        }
    }

    // without a prekey
    public init<Bytes: ContiguousBytes>(registrationId: UInt32,
                                        deviceId: UInt32,
                                        signedPrekeyId: UInt32,
                                        signedPrekey: PublicKey,
                                        signedPrekeySignature: Bytes,
                                        identity identityKey: IdentityKey) throws {
        handle = try signedPrekeySignature.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_pre_key_bundle_new(&result,
                                                     registrationId,
                                                     deviceId,
                                                     ~0,
                                                     nil,
                                                     signedPrekeyId,
                                                     signedPrekey.nativeHandle,
                                                     $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                     $0.count,
                                                     identityKey.publicKey.nativeHandle))
            return result
        }
    }

    public var registrationId: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_pre_key_bundle_get_registration_id($0, handle)
            }
        }
    }

    public var deviceId: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_pre_key_bundle_get_device_id($0, handle)
            }
        }
    }

    public var signedPreKeyId: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_pre_key_bundle_get_signed_pre_key_id($0, handle)
            }
        }
    }

    public var preKeyId: UInt32? {
        let prekey_id = failOnError {
            try invokeFnReturningInteger {
                signal_pre_key_bundle_get_signed_pre_key_id($0, handle)
            }
        }

        if prekey_id == ~0 {
            return nil
        } else {
            return prekey_id
        }
    }

    public var preKeyPublic: PublicKey? {
        return failOnError {
            try invokeFnReturningOptionalPublicKey {
                signal_pre_key_bundle_get_pre_key_public($0, handle)
            }
        }
    }

    public var identityKey: IdentityKey {
        let pk = failOnError {
            try invokeFnReturningPublicKey {
                signal_pre_key_bundle_get_identity_key($0, handle)
            }
        }
        return IdentityKey(publicKey: pk)
    }

    public var signedPreKeyPublic: PublicKey {
        return failOnError {
            try invokeFnReturningPublicKey {
                signal_pre_key_bundle_get_signed_pre_key_public($0, handle)
            }
        }
    }

    public var signedPreKeySignature: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_pre_key_bundle_get_signed_pre_key_signature($0, $1, handle)
            }
        }
    }
}
