//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class ServerCertificate: ClonableHandleOwner {
    public init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_server_certificate_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
        super.init(owned: handle!)
    }

    internal override init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_server_certificate_destroy(handle)
    }

    public func keyId() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_server_certificate_get_key_id(nativeHandle, $0)
        }
    }

    public func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_server_certificate_get_serialized(nativeHandle, $0, $1)
        }
    }

    public func certificateBytes() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_server_certificate_get_certificate(nativeHandle, $0, $1)
        }
    }

    public func signatureBytes() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_server_certificate_get_signature(nativeHandle, $0, $1)
        }
    }

    public func publicKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey {
            signal_server_certificate_get_key($0, nativeHandle)
        }
    }
}

public class SenderCertificate: ClonableHandleOwner {
    public init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_sender_certificate_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
        super.init(owned: handle!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_sender_certificate_destroy(handle)
    }

    public func expiration() throws -> UInt64 {
        return try invokeFnReturningInteger {
            signal_sender_certificate_get_expiration(nativeHandle, $0)
        }
    }

    public func deviceId() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_sender_certificate_get_device_id(nativeHandle, $0)
        }
    }

    public func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_sender_certificate_get_serialized(nativeHandle, $0, $1)
        }
    }

    public func certificateBytes() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_sender_certificate_get_certificate(nativeHandle, $0, $1)
        }
    }

    public func signatureBytes() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_sender_certificate_get_signature(nativeHandle, $0, $1)
        }
    }

    public func publicKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey {
            signal_sender_certificate_get_key($0, nativeHandle)
        }
    }

    public func senderUuid() throws -> String? {
        return try invokeFnReturningOptionalString {
            signal_sender_certificate_get_sender_uuid(nativeHandle, $0)
        }
    }

    public func senderE164() throws -> String? {
        return try invokeFnReturningOptionalString {
            signal_sender_certificate_get_sender_e164(nativeHandle, $0)
        }
    }

    public func serverCertificate() throws -> ServerCertificate {
        var handle: OpaquePointer?
        try checkError(signal_sender_certificate_get_server_certificate(&handle, nativeHandle))
        return ServerCertificate(owned: handle!)
    }

    public func validate(trust_root: PublicKey, time: UInt64) throws -> Bool {
        var result: UInt32 = 0
        try checkError(signal_sender_certificate_validate(&result, nativeHandle, trust_root.nativeHandle, time))

        if result == 1 {
            return true
        } else {
            return false
        }
    }

    // Is signal_sender_certificate_preferred_address logic needed on iOS?
}

public func sealedSenderEncrypt<Bytes: ContiguousBytes>(message: Bytes,
                                                        for address: ProtocolAddress,
                                                        from senderCert: SenderCertificate,
                                                        sessionStore: SessionStore,
                                                        identityStore: IdentityKeyStore,
                                                        context: UnsafeMutableRawPointer?) throws -> [UInt8] {
    return try message.withUnsafeBytes { messageBytes in
        try withSessionStore(sessionStore) { ffiSessionStore in
            try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                try invokeFnReturningArray {
                    signal_sealed_session_cipher_encrypt($0, $1,
                                                         address.nativeHandle, senderCert.nativeHandle,
                                                         messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                         messageBytes.count,
                                                         ffiSessionStore, ffiIdentityStore, context)
                }
            }
        }
    }
}
