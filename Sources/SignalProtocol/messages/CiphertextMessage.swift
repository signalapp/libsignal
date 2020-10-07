import SignalFfi

class CiphertextMessage {
    private var handle: OpaquePointer?

    deinit {
        signal_ciphertext_message_destroy(handle)
    }

    internal init(owned rawPtr: OpaquePointer?) {
        handle = rawPtr
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_ciphertext_message_serialize($0, $1, handle)
        }
    }

    func messageType() throws -> UInt8 {
        return try invokeFnReturningInteger {
            signal_ciphertext_message_type($0, handle)
        }
    }
}
