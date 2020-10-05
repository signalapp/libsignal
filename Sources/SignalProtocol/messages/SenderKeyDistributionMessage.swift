import SignalFfi
import Foundation

class SenderKeyDistributionMessage {
    private var handle: OpaquePointer?

    deinit {
        signal_sender_key_distribution_message_destroy(handle)
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }

    init(name: SenderKeyName, store: SenderKeyStore, context: UnsafeMutableRawPointer?) throws {
        try withSenderKeyStore(store) {
            try checkError(signal_create_sender_key_distribution_message(&handle, name.nativeHandle,
                                                                         $0, context))
        }
    }

    init(keyId: UInt32,
         iteration: UInt32,
         chainKey: [UInt8],
         publicKey: PublicKey) throws {

        try checkError(signal_sender_key_distribution_message_new(&handle,
                                                                  keyId,
                                                                  iteration,
                                                                  chainKey,
                                                                  chainKey.count,
                                                                  publicKey.nativeHandle))
    }

    init(bytes: [UInt8]) throws {
        try checkError(signal_sender_key_distribution_message_deserialize(&handle, bytes, bytes.count))
    }

    func getSignatureKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_sender_key_distribution_message_get_signature_key(k, handle) })
    }

    func getId() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_sender_key_distribution_message_get_id(handle, i) })
    }

    func getIteration() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_sender_key_distribution_message_get_iteration(handle, i) })
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_sender_key_distribution_message_serialize(handle,b,bl) })
    }

    func chainKey() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_sender_key_distribution_message_get_chain_key(handle,b,bl) })
    }
}
