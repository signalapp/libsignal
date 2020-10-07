import SignalFfi

public class SignalMessage {
    private var handle: OpaquePointer?

    deinit {
        signal_message_destroy(handle)
    }

    internal init(owned rawPtr: OpaquePointer?) {
        handle = rawPtr
    }

    public init(bytes: [UInt8]) throws {
        try checkError(signal_message_deserialize(&handle, bytes, bytes.count))
    }

    public init(version: UInt8,
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

    public func senderRatchetKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey {
            signal_message_get_sender_ratchet_key($0, handle)
        }
    }

    public func body() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_message_get_body(handle, $0, $1)
        }
    }

    public func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_message_get_serialized(handle, $0, $1)
        }
    }

    public func messageVersion() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_message_get_message_version(handle, $0)
        }
    }

    public func counter() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_message_get_counter(handle, $0)
        }
    }

    public func verifyMac(sender: PublicKey,
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
