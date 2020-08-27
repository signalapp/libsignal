import SignalFfi
import Foundation

class PreKeySignalMessage {
    private var handle: OpaquePointer?;

    deinit {
        signal_pre_key_signal_message_destroy(handle);
    }

    init(bytes: [UInt8]) throws {
        try CheckError(signal_pre_key_signal_message_deserialize(&handle, bytes, bytes.count));
    }

    init(version: UInt8,
         registration_id: UInt32,
         pre_key_id: Optional<UInt32>,
         signed_pre_key_id: UInt32,
         base_key: PublicKey,
         identity_key: PublicKey,
         message: SignalMessage) throws {

        // XXX why is var needed here? pointer arg is const so let should be ok
        var pre_key_id = pre_key_id ?? 0xFFFFFFFF;

        try CheckError(signal_pre_key_signal_message_new(&handle,
                                                         version,
                                                         registration_id,
                                                         &pre_key_id,
                                                         signed_pre_key_id,
                                                         base_key.nativeHandle(),
                                                         identity_key.nativeHandle(),
                                                         message.nativeHandle()));
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_pre_key_signal_message_serialize(handle,b,bl) });
    }

    func getVersion() throws -> UInt32 {
        return try invokeFnReturningUInt32(fn: { (i) in signal_pre_key_signal_message_get_version(handle, i) });
    }

    func getRegistrationId() throws -> UInt32 {
        return try invokeFnReturningUInt32(fn: { (i) in signal_pre_key_signal_message_get_registration_id(handle, i) });
    }

    func getPreKeyId() throws -> Optional<UInt32> {
        let id = try invokeFnReturningUInt32(fn: { (i) in signal_pre_key_signal_message_get_pre_key_id(handle, i) });

        if id == 0xFFFFFFFF {
            return Optional.none;
        } else {
            return Optional.some(id);
        }
    }

    func getSignedPreKeyId() throws -> UInt32 {
        return try invokeFnReturningUInt32(fn: { (i) in signal_pre_key_signal_message_get_signed_pre_key_id(handle, i) });
    }

    func getBaseKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_pre_key_signal_message_get_base_key(k, handle) });
    }

    func getIdentityKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_pre_key_signal_message_get_identity_key(k, handle) });
    }

    func getSignalMessage() throws -> SignalMessage {
        var m : OpaquePointer?;
        try CheckError(signal_pre_key_signal_message_get_signal_message(&m, handle));
        return SignalMessage(raw_ptr: m);
    }

    internal func nativeHandle() -> OpaquePointer? {
        return handle;
    }
}
