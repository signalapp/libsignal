
import SignalFfi
import Foundation

class CiphertextMessage {
    private var handle: OpaquePointer?

    deinit {
        signal_ciphertext_message_destroy(handle)
    }

    internal init(raw_ptr: OpaquePointer?) {
        handle = raw_ptr;
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_ciphertext_message_serialize(b,bl,handle) })
    }

    func messageType() throws -> UInt8 {
        return try invokeFnReturningInteger(fn: { (i) in signal_ciphertext_message_type(i, handle) })
    }
}
