import SignalFfi
import Foundation

class SenderKeyMessage {
    private var handle: OpaquePointer?

    deinit {
        signal_sender_key_message_destroy(handle)
    }

    init(key_id: UInt32,
         iteration: UInt32,
         chain_key: [UInt8],
         ciphertext: [UInt8],
         pk: PrivateKey) throws {

        try CheckError(signal_sender_key_message_new(&handle,
                                                     key_id,
                                                     iteration,
                                                     ciphertext,
                                                     ciphertext.count,
                                                     pk.nativeHandle))
    }

    init(bytes: [UInt8]) throws {
        try CheckError(signal_sender_key_message_deserialize(&handle, bytes, bytes.count))
    }

    func getKeyId() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_sender_key_message_get_key_id(handle, i) })
    }

    func getIteration() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_sender_key_message_get_iteration(handle, i) })
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_sender_key_message_serialize(handle,b,bl) })
    }

    func getCiphertext() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_sender_key_message_get_cipher_text(handle,b,bl) })
    }

    func verifySignature(key: PrivateKey) throws -> Bool {
        var result: Bool = false
        try CheckError(signal_sender_key_message_verify_signature(&result, handle, key.nativeHandle))
        return result
    }
}
