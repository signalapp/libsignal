//
// Copyright 2021 Signal Messenger, LLC
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

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_server_certificate_destroy(handle)
    }

    public var keyId: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_server_certificate_get_key_id($0, nativeHandle)
            }
        }
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_server_certificate_get_serialized($0, $1, nativeHandle)
            }
        }
    }

    public var certificateBytes: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_server_certificate_get_certificate($0, $1, nativeHandle)
            }
        }
    }

    public var signatureBytes: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_server_certificate_get_signature($0, $1, nativeHandle)
            }
        }
    }

    public var publicKey: PublicKey {
        return failOnError {
            try invokeFnReturningPublicKey {
                signal_server_certificate_get_key($0, nativeHandle)
            }
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

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_sender_certificate_destroy(handle)
    }

    public var expiration: UInt64 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_sender_certificate_get_expiration($0, nativeHandle)
            }
        }
    }

    public var deviceId: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_sender_certificate_get_device_id($0, nativeHandle)
            }
        }
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_sender_certificate_get_serialized($0, $1, nativeHandle)
            }
        }
    }

    public var certificateBytes: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_sender_certificate_get_certificate($0, $1, nativeHandle)
            }
        }
    }

    public var signatureBytes: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_sender_certificate_get_signature($0, $1, nativeHandle)
            }
        }
    }

    public var publicKey: PublicKey {
        return failOnError {
            try invokeFnReturningPublicKey {
                signal_sender_certificate_get_key($0, nativeHandle)
            }
        }
    }

    public var senderUuid: String {
        return failOnError {
            try invokeFnReturningString {
                signal_sender_certificate_get_sender_uuid($0, nativeHandle)
            }
        }
    }

    public var senderE164: String? {
        return failOnError {
            try invokeFnReturningOptionalString {
                signal_sender_certificate_get_sender_e164($0, nativeHandle)
            }
        }
    }

    public var sender: SealedSenderAddress {
        return try! SealedSenderAddress(e164: self.senderE164, uuidString: self.senderUuid, deviceId: self.deviceId)
    }

    public var serverCertificate: ServerCertificate {
        var handle: OpaquePointer?
        failOnError(signal_sender_certificate_get_server_certificate(&handle, nativeHandle))
        return ServerCertificate(owned: handle!)
    }

    public func validate(trustRoot: PublicKey, time: UInt64) throws -> Bool {
        var result: Bool = false
        try checkError(signal_sender_certificate_validate(&result, nativeHandle, trustRoot.nativeHandle, time))
        return result
    }
}
