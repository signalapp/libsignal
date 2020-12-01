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

    // For testing
    public init(keyId: UInt32, publicKey: PublicKey, trustRoot: PrivateKey) throws {
        var result: OpaquePointer?
        try checkError(signal_server_certificate_new(&result, keyId, publicKey.nativeHandle, trustRoot.nativeHandle))
        super.init(owned: result!)
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

    // For testing
    public init(sender: SealedSenderAddress, publicKey: PublicKey, expiration: UInt64, signerCertificate: ServerCertificate, signerKey: PrivateKey) throws {
        var result: OpaquePointer?
        try checkError(signal_sender_certificate_new(&result,
                                                     sender.uuidString,
                                                     sender.e164,
                                                     sender.deviceId,
                                                     publicKey.nativeHandle,
                                                     expiration,
                                                     signerCertificate.nativeHandle,
                                                     signerKey.nativeHandle))
        super.init(owned: result!)
    }

    internal override init(owned handle: OpaquePointer) {
        super.init(owned: handle)
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

    public func sender() throws -> SealedSenderAddress {
        return try SealedSenderAddress(e164: self.senderE164(),
                                       uuidString: self.senderUuid(),
                                       deviceId: self.deviceId())
    }

    public func serverCertificate() throws -> ServerCertificate {
        var handle: OpaquePointer?
        try checkError(signal_sender_certificate_get_server_certificate(&handle, nativeHandle))
        return ServerCertificate(owned: handle!)
    }

    public func validate(trustRoot: PublicKey, time: UInt64) throws -> Bool {
        var result: Bool = false
        try checkError(signal_sender_certificate_validate(&result, nativeHandle, trustRoot.nativeHandle, time))
        return result
    }
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

public class UnidentifiedSenderMessageContent: ClonableHandleOwner {
    public init<Bytes: ContiguousBytes>(message: Bytes,
                                        trustRoot: PublicKey,
                                        timestamp: UInt64,
                                        identityStore: IdentityKeyStore,
                                        context: UnsafeMutableRawPointer?) throws {
        var result: OpaquePointer?
        try message.withUnsafeBytes { messageBytes in
            try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                try checkError(
                    signal_sealed_session_cipher_decrypt_to_usmc(
                        &result,
                        messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        messageBytes.count,
                        trustRoot.nativeHandle,
                        timestamp,
                        ffiIdentityStore,
                        context))
            }
        }
        super.init(owned: result!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_unidentified_sender_message_content_destroy(handle)
    }

    public func senderCertificate() throws -> SenderCertificate {
        var result: OpaquePointer?
        try checkError(signal_unidentified_sender_message_content_get_sender_cert(&result, self.nativeHandle))
        return SenderCertificate(owned: result!)
    }

    public func messageType() throws -> CiphertextMessage.MessageType {
        let rawType = try invokeFnReturningInteger {
            signal_unidentified_sender_message_content_get_msg_type($0, self.nativeHandle)
        }
        return .init(rawValue: rawType)
    }

    public func contents() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_unidentified_sender_message_content_get_contents(self.nativeHandle, $0, $1)
        }
    }
}

public struct SealedSenderAddress: Hashable {
    public var e164: String?
    public var uuidString: String?
    public var deviceId: UInt32

    public init(e164: String?, uuidString: String?, deviceId: UInt32) throws {
        guard e164 != nil || uuidString != nil else {
            throw SignalError.invalidArgument("SealedSenderAddress must have an e164 phone number or a UUID (or both)")
        }
        self.e164 = e164
        self.uuidString = uuidString
        self.deviceId = deviceId
    }
}

public struct SealedSenderResult {
    public var message: [UInt8]
    public var sender: SealedSenderAddress
}

public func sealedSenderDecrypt<Bytes: ContiguousBytes>(message: Bytes,
                                                        from localAddress: SealedSenderAddress,
                                                        trustRoot: PublicKey,
                                                        timestamp: UInt64,
                                                        sessionStore: SessionStore,
                                                        identityStore: IdentityKeyStore,
                                                        preKeyStore: PreKeyStore,
                                                        signedPreKeyStore: SignedPreKeyStore,
                                                        context: UnsafeMutableRawPointer?) throws -> SealedSenderResult {
    var senderE164: UnsafePointer<CChar>?
    var senderUUID: UnsafePointer<CChar>?
    var senderDeviceId: UInt32 = 0

    let plaintext = try message.withUnsafeBytes { messageBytes in
        try withSessionStore(sessionStore) { ffiSessionStore in
            try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                try withPreKeyStore(preKeyStore) { ffiPreKeyStore in
                    try withSignedPreKeyStore(signedPreKeyStore) { ffiSignedPreKeyStore in
                        try invokeFnReturningArray {
                            signal_sealed_session_cipher_decrypt(
                                $0,
                                $1,
                                &senderE164,
                                &senderUUID,
                                &senderDeviceId,
                                messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                messageBytes.count,
                                trustRoot.nativeHandle,
                                timestamp,
                                localAddress.e164,
                                localAddress.uuidString,
                                localAddress.deviceId,
                                ffiSessionStore,
                                ffiIdentityStore,
                                ffiPreKeyStore,
                                ffiSignedPreKeyStore,
                                context)
                        }
                    }
                }
            }
        }
    }

    defer {
        signal_free_string(senderE164)
        signal_free_string(senderUUID)
    }

    return SealedSenderResult(message: plaintext,
                              sender: try SealedSenderAddress(e164: senderE164.map(String.init(cString:)),
                                                              uuidString: senderUUID.map(String.init(cString:)),
                                                              deviceId: senderDeviceId))
}
