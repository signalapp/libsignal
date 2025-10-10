//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class UnidentifiedSenderMessageContent: NativeHandleOwner<SignalMutPointerUnidentifiedSenderMessageContent> {
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
        bytes: Bytes
    ) throws {
        let result = try bytes.withUnsafeBorrowedBuffer { bytes in
            try invokeFnReturningValueByPointer(.init()) {
                signal_unidentified_sender_message_content_deserialize($0, bytes)
            }
        }
        self.init(owned: NonNull(result)!)
    }

    public convenience init<Bytes: ContiguousBytes>(
        message sealedSenderMessage: Bytes,
        identityStore: IdentityKeyStore,
        context: StoreContext
    ) throws {
        let result = try sealedSenderMessage.withUnsafeBorrowedBuffer { messageBuffer in
            try withIdentityKeyStore(identityStore, context) { ffiIdentityStore in
                try invokeFnReturningValueByPointer(.init()) {
                    signal_sealed_session_cipher_decrypt_to_usmc(
                        $0,
                        messageBuffer,
                        ffiIdentityStore
                    )
                }
            }
        }
        self.init(owned: NonNull(result)!)
    }

    public convenience init<GroupIdBytes: ContiguousBytes>(
        _ message: CiphertextMessage,
        from sender: SenderCertificate,
        contentHint: ContentHint,
        groupId: GroupIdBytes
    ) throws {
        let result = try withAllBorrowed(message, sender, .bytes(groupId)) {
            messageHandle,
            senderHandle,
            groupIdBuffer in
            try invokeFnReturningValueByPointer(.init()) {
                signal_unidentified_sender_message_content_new(
                    $0,
                    messageHandle.const(),
                    senderHandle.const(),
                    contentHint.rawValue,
                    groupIdBuffer
                )
            }
        }
        self.init(owned: NonNull(result)!)
    }

    public convenience init<MessageBytes: ContiguousBytes, GroupIdBytes: ContiguousBytes>(
        _ message: MessageBytes,
        type: CiphertextMessage.MessageType,
        from sender: SenderCertificate,
        contentHint: ContentHint,
        groupId: GroupIdBytes
    ) throws {
        let result = try withAllBorrowed(.bytes(message), sender, .bytes(groupId)) {
            messageBuffer,
            senderHandle,
            groupIdBuffer in
            try invokeFnReturningValueByPointer(.init()) {
                signal_unidentified_sender_message_content_new_from_content_and_type(
                    $0,
                    messageBuffer,
                    type.rawValue,
                    senderHandle.const(),
                    contentHint.rawValue,
                    groupIdBuffer
                )
            }
        }
        self.init(owned: NonNull(result)!)
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerUnidentifiedSenderMessageContent>
    ) -> SignalFfiErrorRef? {
        return signal_unidentified_sender_message_content_destroy(handle.pointer)
    }

    public var senderCertificate: SenderCertificate {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_unidentified_sender_message_content_get_sender_cert($0, nativeHandle.const())
                }
            }
        }
    }

    public var messageType: CiphertextMessage.MessageType {
        let rawType = withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_unidentified_sender_message_content_get_msg_type($0, nativeHandle.const())
                }
            }
        }
        return .init(rawValue: rawType)
    }

    public var contents: Data {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_unidentified_sender_message_content_get_contents($0, nativeHandle.const())
                }
            }
        }
    }

    public var groupId: Data? {
        let result = withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_unidentified_sender_message_content_get_group_id_or_empty($0, nativeHandle.const())
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
                    signal_unidentified_sender_message_content_get_content_hint($0, nativeHandle.const())
                }
            }
        }
        return .init(rawValue: rawHint)
    }

    public func serialize() -> Data {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_unidentified_sender_message_content_serialize($0, nativeHandle.const())
                }
            }
        }
    }
}

extension SignalMutPointerUnidentifiedSenderMessageContent: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerUnidentifiedSenderMessageContent

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

extension SignalConstPointerUnidentifiedSenderMessageContent: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

public func sealedSenderEncrypt(
    _ content: UnidentifiedSenderMessageContent,
    for recipient: ProtocolAddress,
    identityStore: IdentityKeyStore,
    context: StoreContext
) throws -> Data {
    return try withAllBorrowed(recipient, content) { recipientHandle, contentHandle in
        try withIdentityKeyStore(identityStore, context) { ffiIdentityStore in
            try invokeFnReturningData {
                signal_sealed_session_cipher_encrypt(
                    $0,
                    recipientHandle.const(),
                    contentHandle.const(),
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
) throws -> Data {
    let sessions = try sessionStore.loadExistingSessions(for: recipients, context: context)
    // Use withExtendedLifetime instead of withNativeHandle for the arrays of wrapper objects,
    // which aren't compatible with withNativeHandle's simple lexical scoping.
    return try withExtendedLifetime((recipients, sessions)) {
        let recipientHandles = recipients.map { SignalConstPointerProtocolAddress(raw: $0.unsafeNativeHandle) }
        let sessionHandles = sessions.map { SignalConstPointerSessionRecord(raw: $0.unsafeNativeHandle) }
        return try withAllBorrowed(
            content,
            .slice(recipientHandles),
            .slice(sessionHandles),
            .bytes(ServiceId.concatenatedFixedWidthBinary(excludedRecipients))
        ) { contentHandle, recipientHandlesBuffer, sessionHandlesBuffer, excludedRecipientsBuffer in
            try withIdentityKeyStore(identityStore, context) { ffiIdentityStore in
                try invokeFnReturningData {
                    signal_sealed_sender_multi_recipient_encrypt(
                        $0,
                        recipientHandlesBuffer,
                        sessionHandlesBuffer,
                        excludedRecipientsBuffer,
                        contentHandle.const(),
                        ffiIdentityStore
                    )
                }
            }
        }
    }
}

// For testing only.
internal func sealedSenderMultiRecipientMessageForSingleRecipient(_ message: Data) throws -> Data {
    return try message.withUnsafeBorrowedBuffer { message in
        try invokeFnReturningData {
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
