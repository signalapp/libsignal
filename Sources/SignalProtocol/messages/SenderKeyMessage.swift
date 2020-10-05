import SignalFfi
import Foundation

class SenderKeyMessage {
    private var handle: OpaquePointer?

    deinit {
        signal_sender_key_message_destroy(handle)
    }

    init(keyId: UInt32,
         iteration: UInt32,
         chainKey: [UInt8],
         ciphertext: [UInt8],
         privateKey: PrivateKey) throws {

        try checkError(signal_sender_key_message_new(&handle,
                                                     keyId,
                                                     iteration,
                                                     ciphertext,
                                                     ciphertext.count,
                                                     privateKey.nativeHandle))
    }

    init(bytes: [UInt8]) throws {
        try checkError(signal_sender_key_message_deserialize(&handle, bytes, bytes.count))
    }

    func keyId() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_sender_key_message_get_key_id(handle, i) })
    }

    func iteration() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_sender_key_message_get_iteration(handle, i) })
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_sender_key_message_serialize(handle,b,bl) })
    }

    func ciphertext() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_sender_key_message_get_cipher_text(handle,b,bl) })
    }

    func verifySignature(against key: PrivateKey) throws -> Bool {
        var result: Bool = false
        try checkError(signal_sender_key_message_verify_signature(&result, handle, key.nativeHandle))
        return result
    }
}
