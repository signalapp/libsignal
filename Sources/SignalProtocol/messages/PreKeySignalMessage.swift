import SignalFfi
import Foundation

class PreKeySignalMessage {
    private var handle: OpaquePointer?

    deinit {
        signal_pre_key_signal_message_destroy(handle)
    }

    init(bytes: [UInt8]) throws {
        try checkError(signal_pre_key_signal_message_deserialize(&handle, bytes, bytes.count))
    }

    init(version: UInt8,
         registrationId: UInt32,
         preKeyId: Optional<UInt32>,
         signedPreKeyId: UInt32,
         baseKey: PublicKey,
         identityKey: PublicKey,
         message: SignalMessage) throws {

        // XXX why is var needed here? pointer arg is const so let should be ok
        var pre_key_id = preKeyId ?? 0xFFFFFFFF

        try checkError(signal_pre_key_signal_message_new(&handle,
                                                         version,
                                                         registrationId,
                                                         &pre_key_id,
                                                         signedPreKeyId,
                                                         baseKey.nativeHandle,
                                                         identityKey.nativeHandle,
                                                         message.nativeHandle))
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_pre_key_signal_message_serialize(handle,b,bl) })
    }

    func getVersion() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_pre_key_signal_message_get_version(handle, i) })
    }

    func getRegistrationId() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_pre_key_signal_message_get_registration_id(handle, i) })
    }

    func getPreKeyId() throws -> Optional<UInt32> {
        let id = try invokeFnReturningInteger(fn: { (i) in signal_pre_key_signal_message_get_pre_key_id(handle, i) })

        if id == 0xFFFFFFFF {
            return Optional.none
        } else {
            return Optional.some(id)
        }
    }

    func getSignedPreKeyId() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_pre_key_signal_message_get_signed_pre_key_id(handle, i) })
    }

    func getBaseKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_pre_key_signal_message_get_base_key(k, handle) })
    }

    func getIdentityKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_pre_key_signal_message_get_identity_key(k, handle) })
    }

    func getSignalMessage() throws -> SignalMessage {
        var m : OpaquePointer?
        try checkError(signal_pre_key_signal_message_get_signal_message(&m, handle))
        return SignalMessage(owned: m)
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }
}
