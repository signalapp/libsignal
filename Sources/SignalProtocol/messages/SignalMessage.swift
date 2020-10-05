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
        try checkError(signal_message_deserialize(&handle, bytes, bytes.count))
    }

    init(version: UInt8,
         macKey: [UInt8],
         senderRatchetKey: PublicKey,
         counter: UInt32,
         previousCounter: UInt32,
         ciphertext: [UInt8],
         sender senderIdentityKey: PublicKey,
         receiver receiverIdentityKey: PublicKey) throws {
        try checkError(signal_message_new(&handle,
                                          version,
                                          macKey,
                                          macKey.count,
                                          senderRatchetKey.nativeHandle,
                                          counter,
                                          previousCounter,
                                          ciphertext,
                                          ciphertext.count,
                                          senderIdentityKey.nativeHandle,
                                          receiverIdentityKey.nativeHandle))
    }

    func senderRatchetKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_message_get_sender_ratchet_key(k, handle) })
    }

    func body() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_message_get_body(handle,b,bl) })
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_message_get_serialized(handle,b,bl) })
    }

    func messageVersion() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_message_get_message_version(handle, i) })
    }

    func counter() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_message_get_counter(handle, i) })
    }

    func verifyMac(sender: PublicKey,
                   receiver: PublicKey,
                   macKey: [UInt8]) throws -> Bool {
        var result: Bool = false
        try checkError(signal_message_verify_mac(&result,
                                                 handle,
                                                 sender.nativeHandle,
                                                 receiver.nativeHandle,
                                                 macKey,
                                                 macKey.count))
        return result
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }

}
