//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

@inlinable
public func sealedSenderEncrypt<Bytes: ContiguousBytes>(
    message: Bytes,
    for address: ProtocolAddress,
    from senderCert: SenderCertificate,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    context: StoreContext
) throws -> [UInt8] {
    let ciphertextMessage = try signalEncrypt(
        message: message,
        for: address,
        sessionStore: sessionStore,
        identityStore: identityStore,
        context: context
    )

    let usmc = try UnidentifiedSenderMessageContent(
        ciphertextMessage,
        from: senderCert,
        contentHint: .default,
        groupId: []
    )

    return try sealedSenderEncrypt(usmc, for: address, identityStore: identityStore, context: context)
}

public class UnidentifiedSenderMessageContent: NativeHandleOwner {
    public struct ContentHint: RawRepresentable, Hashable, Sendable {
        public var rawValue: UInt32
        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        internal init(_ knownType: SignalContentHint) {
            self.init(rawValue: UInt32(knownType.rawValue))
        }

        public static var `default`: Self {
            return Self(SignalContentHintDefault)
        }

        public static var resendable: Self {
            return Self(SignalContentHintResendable)
        }

        public static var implicit: Self {
            return Self(SignalContentHintImplicit)
        }
    }

    public convenience init<Bytes: ContiguousBytes>(
        message sealedSenderMessage: Bytes,
        identityStore: IdentityKeyStore,
        context: StoreContext
    ) throws {
        var result: OpaquePointer?
        try sealedSenderMessage.withUnsafeBorrowedBuffer { messageBuffer in
            try withIdentityKeyStore(identityStore, context) { ffiIdentityStore in
                try checkError(
                    signal_sealed_session_cipher_decrypt_to_usmc(
                        &result,
                        messageBuffer,
                        ffiIdentityStore
                    ))
            }
        }
        self.init(owned: result!)
    }

    public convenience init<GroupIdBytes: ContiguousBytes>(
        _ message: CiphertextMessage,
        from sender: SenderCertificate,
        contentHint: ContentHint,
        groupId: GroupIdBytes
    ) throws {
        var result: OpaquePointer?
        try withNativeHandles(message, sender) { messageHandle, senderHandle in
            try groupId.withUnsafeBorrowedBuffer { groupIdBuffer in
                try checkError(
                    signal_unidentified_sender_message_content_new(
                        &result,
                        messageHandle,
                        senderHandle,
                        contentHint.rawValue,
                        groupIdBuffer
                    ))
            }
        }
        self.init(owned: result!)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_unidentified_sender_message_content_destroy(handle)
    }

    public var senderCertificate: SenderCertificate {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_unidentified_sender_message_content_get_sender_cert($0, nativeHandle)
                }
            }
        }
    }

    public var messageType: CiphertextMessage.MessageType {
        let rawType = withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_unidentified_sender_message_content_get_msg_type($0, nativeHandle)
                }
            }
        }
        return .init(rawValue: rawType)
    }

    public var contents: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_unidentified_sender_message_content_get_contents($0, nativeHandle)
                }
            }
        }
    }

    public var groupId: [UInt8]? {
        let result = withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_unidentified_sender_message_content_get_group_id_or_empty($0, nativeHandle)
                }
            }
        }
        if result.isEmpty {
            return nil
        }
        return result
    }

    public var contentHint: ContentHint {
        let rawHint = withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_unidentified_sender_message_content_get_content_hint($0, nativeHandle)
                }
            }
        }
        return .init(rawValue: rawHint)
    }
}

public func sealedSenderEncrypt(
    _ content: UnidentifiedSenderMessageContent,
    for recipient: ProtocolAddress,
    identityStore: IdentityKeyStore,
    context: StoreContext
) throws -> [UInt8] {
    return try withNativeHandles(recipient, content) { recipientHandle, contentHandle in
        try withIdentityKeyStore(identityStore, context) { ffiIdentityStore in
            try invokeFnReturningArray {
                signal_sealed_session_cipher_encrypt(
                    $0,
                    recipientHandle,
                    contentHandle,
                    ffiIdentityStore
                )
            }
        }
    }
}

public func sealedSenderMultiRecipientEncrypt(
    _ content: UnidentifiedSenderMessageContent,
    for recipients: [ProtocolAddress],
    excludedRecipients: [ServiceId] = [],
    identityStore: IdentityKeyStore,
    sessionStore: SessionStore,
    context: StoreContext
) throws -> [UInt8] {
    let sessions = try sessionStore.loadExistingSessions(for: recipients, context: context)
    // Use withExtendedLifetime instead of withNativeHandle for the arrays of wrapper objects,
    // which aren't compatible with withNativeHandle's simple lexical scoping.
    return try withExtendedLifetime((recipients, sessions)) {
        let recipientHandles = recipients.map { $0.unsafeNativeHandle }
        let sessionHandles = sessions.map { $0.unsafeNativeHandle }
        return try content.withNativeHandle { contentHandle in
            try recipientHandles.withUnsafeBufferPointer { recipientHandles in
                let recipientHandlesBuffer = SignalBorrowedSliceOfProtocolAddress(base: recipientHandles.baseAddress, length: recipientHandles.count)
                return try sessionHandles.withUnsafeBufferPointer { sessionHandles in
                    let sessionHandlesBuffer = SignalBorrowedSliceOfSessionRecord(base: sessionHandles.baseAddress, length: sessionHandles.count)
                    return try ServiceId.concatenatedFixedWidthBinary(excludedRecipients).withUnsafeBorrowedBuffer { excludedRecipientsBuffer in
                        try withIdentityKeyStore(identityStore, context) { ffiIdentityStore in
                            try invokeFnReturningArray {
                                signal_sealed_sender_multi_recipient_encrypt(
                                    $0,
                                    recipientHandlesBuffer,
                                    sessionHandlesBuffer,
                                    excludedRecipientsBuffer,
                                    contentHandle,
                                    ffiIdentityStore
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// For testing only.
internal func sealedSenderMultiRecipientMessageForSingleRecipient(_ message: [UInt8]) throws -> [UInt8] {
    return try message.withUnsafeBorrowedBuffer { message in
        try invokeFnReturningArray {
            signal_sealed_sender_multi_recipient_message_for_single_recipient($0, message)
        }
    }
}

public struct SealedSenderAddress: Hashable, Sendable {
    public var e164: String?
    public var uuidString: String
    public var deviceId: UInt32

    public init(e164: String?, uuidString: String, deviceId: UInt32) throws {
        self.e164 = e164
        self.uuidString = uuidString
        self.deviceId = deviceId
    }

    public init(e164: String? = nil, aci: Aci, deviceId: UInt32) throws {
        self.e164 = e164
        self.uuidString = aci.serviceIdString
        self.deviceId = deviceId
    }

    /// Returns an ACI if the sender is a valid UUID, `nil` otherwise.
    ///
    /// In a future release SealedSenderAddress will *only* support ACIs.
    public var senderAci: Aci! {
        return try? Aci.parseFrom(serviceIdString: self.uuidString)
    }
}

public struct SealedSenderResult: Sendable {
    public var message: [UInt8]
    public var sender: SealedSenderAddress
}

public func sealedSenderDecrypt<Bytes: ContiguousBytes>(
    message: Bytes,
    from localAddress: SealedSenderAddress,
    trustRoot: PublicKey,
    timestamp: UInt64,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    preKeyStore: PreKeyStore,
    signedPreKeyStore: SignedPreKeyStore,
    context: StoreContext
) throws -> SealedSenderResult {
    var senderE164: UnsafePointer<CChar>?
    var senderUUID: UnsafePointer<CChar>?
    var senderDeviceId: UInt32 = 0

    let plaintext = try trustRoot.withNativeHandle { trustRootHandle in
        try message.withUnsafeBorrowedBuffer { messageBuffer in
            try withSessionStore(sessionStore, context) { ffiSessionStore in
                try withIdentityKeyStore(identityStore, context) { ffiIdentityStore in
                    try withPreKeyStore(preKeyStore, context) { ffiPreKeyStore in
                        try withSignedPreKeyStore(signedPreKeyStore, context) { ffiSignedPreKeyStore in
                            try invokeFnReturningArray {
                                signal_sealed_session_cipher_decrypt(
                                    $0,
                                    &senderE164,
                                    &senderUUID,
                                    &senderDeviceId,
                                    messageBuffer,
                                    trustRootHandle,
                                    timestamp,
                                    localAddress.e164,
                                    localAddress.uuidString,
                                    localAddress.deviceId,
                                    ffiSessionStore,
                                    ffiIdentityStore,
                                    ffiPreKeyStore,
                                    ffiSignedPreKeyStore
                                )
                            }
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

    return SealedSenderResult(
        message: plaintext,
        sender: try SealedSenderAddress(
            e164: senderE164.map(String.init(cString:)),
            uuidString: String(cString: senderUUID!),
            deviceId: senderDeviceId
        )
    )
}
