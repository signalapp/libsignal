//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ServerCertificate: NativeHandleOwner, @unchecked Sendable {
    public convenience init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(signal_server_certificate_deserialize(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    // For testing
    public convenience init(keyId: UInt32, publicKey: PublicKey, trustRoot: PrivateKey) throws {
        var result: OpaquePointer?
        try withNativeHandles(publicKey, trustRoot) { publicKeyHandle, trustRootHandle in
            try checkError(signal_server_certificate_new(&result, keyId, publicKeyHandle, trustRootHandle))
        }
        self.init(owned: result!)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_server_certificate_destroy(handle)
    }

    public var keyId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_server_certificate_get_key_id($0, nativeHandle)
                }
            }
        }
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_server_certificate_get_serialized($0, nativeHandle)
                }
            }
        }
    }

    public var certificateBytes: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_server_certificate_get_certificate($0, nativeHandle)
                }
            }
        }
    }

    public var signatureBytes: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_server_certificate_get_signature($0, nativeHandle)
                }
            }
        }
    }

    public var publicKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_server_certificate_get_key($0, nativeHandle)
                }
            }
        }
    }
}

public class SenderCertificate: NativeHandleOwner, @unchecked Sendable {
    public convenience init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(signal_sender_certificate_deserialize(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    // For testing
    public convenience init(sender: SealedSenderAddress, publicKey: PublicKey, expiration: UInt64, signerCertificate: ServerCertificate, signerKey: PrivateKey) throws {
        var result: OpaquePointer?
        try withNativeHandles(publicKey, signerCertificate, signerKey) { publicKeyHandle, signerCertificateHandle, signerKeyHandle in
            try checkError(signal_sender_certificate_new(
                &result,
                sender.uuidString,
                sender.e164,
                sender.deviceId,
                publicKeyHandle,
                expiration,
                signerCertificateHandle,
                signerKeyHandle
            ))
        }
        self.init(owned: result!)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_sender_certificate_destroy(handle)
    }

    public var expiration: UInt64 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_sender_certificate_get_expiration($0, nativeHandle)
                }
            }
        }
    }

    public var deviceId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_sender_certificate_get_device_id($0, nativeHandle)
                }
            }
        }
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_sender_certificate_get_serialized($0, nativeHandle)
                }
            }
        }
    }

    public var certificateBytes: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_sender_certificate_get_certificate($0, nativeHandle)
                }
            }
        }
    }

    public var signatureBytes: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_sender_certificate_get_signature($0, nativeHandle)
                }
            }
        }
    }

    public var publicKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_sender_certificate_get_key($0, nativeHandle)
                }
            }
        }
    }

    public var senderUuid: String {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningString {
                    signal_sender_certificate_get_sender_uuid($0, nativeHandle)
                }
            }
        }
    }

    /// Returns an ACI if the sender is a valid UUID, `nil` otherwise.
    ///
    /// In a future release SenderCertificate will *only* support ACIs.
    public var senderAci: Aci! {
        return try? Aci.parseFrom(serviceIdString: self.senderUuid)
    }

    public var senderE164: String? {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningOptionalString {
                    signal_sender_certificate_get_sender_e164($0, nativeHandle)
                }
            }
        }
    }

    public var sender: SealedSenderAddress {
        return failOnError {
            try SealedSenderAddress(e164: self.senderE164, uuidString: self.senderUuid, deviceId: self.deviceId)
        }
    }

    public var serverCertificate: ServerCertificate {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_sender_certificate_get_server_certificate($0, nativeHandle)
                }
            }
        }
    }

    public func validate(trustRoot: PublicKey, time: UInt64) throws -> Bool {
        var result = false
        try withNativeHandles(self, trustRoot) { certificateHandle, trustRootHandle in
            try checkError(signal_sender_certificate_validate(&result, certificateHandle, trustRootHandle, time))
        }
        return result
    }
}
