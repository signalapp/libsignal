import SignalFfi

public class CiphertextMessage {
    private var handle: OpaquePointer?

    public struct MessageType: RawRepresentable, Hashable {
        public var rawValue: UInt8
        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        internal init(_ knownType: SignalCiphertextMessageType) {
            self.init(rawValue: UInt8(knownType.rawValue))
        }

        public static var whisper: Self {
            return Self(SignalCiphertextMessageType_Whisper)
        }
        public static var preKey: Self {
            return Self(SignalCiphertextMessageType_PreKey)
        }
        public static var senderKey: Self {
            return Self(SignalCiphertextMessageType_SenderKey)
        }
        public static var senderKeyDistribution: Self {
            return Self(SignalCiphertextMessageType_SenderKeyDistribution)
        }
    }

    deinit {
        signal_ciphertext_message_destroy(handle)
    }

    internal init(owned rawPtr: OpaquePointer?) {
        handle = rawPtr
    }

    public func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_ciphertext_message_serialize($0, $1, handle)
        }
    }

    public func messageType() throws -> MessageType {
        return MessageType(rawValue: try invokeFnReturningInteger {
            signal_ciphertext_message_type($0, handle)
        })
    }
}
