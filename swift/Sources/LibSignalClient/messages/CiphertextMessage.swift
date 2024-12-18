//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi

public class CiphertextMessage: NativeHandleOwner<SignalMutPointerCiphertextMessage> {
    public struct MessageType: RawRepresentable, Hashable, Sendable {
        public var rawValue: UInt8
        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        internal init(_ knownType: SignalCiphertextMessageType) {
            self.init(rawValue: UInt8(knownType.rawValue))
        }

        public static var whisper: Self {
            return Self(SignalCiphertextMessageTypeWhisper)
        }

        public static var preKey: Self {
            return Self(SignalCiphertextMessageTypePreKey)
        }

        public static var senderKey: Self {
            return Self(SignalCiphertextMessageTypeSenderKey)
        }

        public static var plaintext: Self {
            return Self(SignalCiphertextMessageTypePlaintext)
        }
    }

    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerCiphertextMessage>) -> SignalFfiErrorRef? {
        return signal_ciphertext_message_destroy(handle.pointer)
    }

    public convenience init(_ plaintextContent: PlaintextContent) {
        var result = SignalMutPointerCiphertextMessage()
        plaintextContent.withNativeHandle { plaintextContentHandle in
            failOnError(signal_ciphertext_message_from_plaintext_content(&result, plaintextContentHandle.const()))
        }
        self.init(owned: NonNull(result)!)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_ciphertext_message_serialize($0, nativeHandle.const())
                }
            }
        }
    }

    public var messageType: MessageType {
        let rawValue = withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_ciphertext_message_type($0, nativeHandle.const())
                }
            }
        }
        return MessageType(rawValue: rawValue)
    }
}

extension SignalMutPointerCiphertextMessage: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerCiphertextMessage

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

extension SignalConstPointerCiphertextMessage: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
