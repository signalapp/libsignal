import SignalFfi
import Foundation

class SignalMessage {
    private var handle: OpaquePointer?

    deinit {
        signal_message_destroy(handle)
    }

    internal init(owned raw_ptr: OpaquePointer?) {
        handle = raw_ptr
    }

    init(bytes: [UInt8]) throws {
        try CheckError(signal_message_deserialize(&handle, bytes, bytes.count))
    }

    init(version: UInt8,
         mac_key: [UInt8],
         sender_ratchet_key: PublicKey,
         counter: UInt32,
         previous_counter: UInt32,
         ciphertext: [UInt8],
         sender_identity_key: PublicKey,
         receiver_identity_key: PublicKey) throws {
        try CheckError(signal_message_new(&handle,
                                          version,
                                          mac_key,
                                          mac_key.count,
                                          sender_ratchet_key.nativeHandle,
                                          counter,
                                          previous_counter,
                                          ciphertext,
                                          ciphertext.count,
                                          sender_identity_key.nativeHandle,
                                          receiver_identity_key.nativeHandle))
    }

    func getSenderRatchetKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_message_get_sender_ratchet_key(k, handle) })
    }

    func getBody() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_message_get_body(handle,b,bl) })
    }

    func getSerialized() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_message_get_serialized(handle,b,bl) })
    }

    func getMessageVersion() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_message_get_message_version(handle, i) })
    }

    func getCounter() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_message_get_counter(handle, i) })
    }

    func verifyMac(sender_identity_key: PublicKey,
                   receiver_identity_key: PublicKey,
                   mac_key: [UInt8]) throws -> Bool {
        var result: Bool = false
        try CheckError(signal_message_verify_mac(&result,
                                                 handle,
                                                 sender_identity_key.nativeHandle,
                                                 receiver_identity_key.nativeHandle,
                                                 mac_key,
                                                 mac_key.count))
        return result
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }

}
