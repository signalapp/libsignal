import SignalFfi
import Foundation

class SignedPreKeyRecord {
    private var handle: OpaquePointer?;

    deinit {
        signal_signed_pre_key_record_destroy(handle);
    }

    init(bytes: [UInt8]) throws {
        try CheckError(signal_signed_pre_key_record_deserialize(&handle, bytes, bytes.count));
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_signed_pre_key_record_serialize(handle,b,bl) });
    }

    func getId() throws -> UInt32 {
        return try invokeFnReturningUInt32(fn: { (i) in signal_signed_pre_key_record_get_id(handle, i) });
    }

    func getTimestamp() throws -> UInt64 {
        return try invokeFnReturningUInt64(fn: { (i) in signal_signed_pre_key_record_get_timestamp(handle, i) });
    }

    func getPublicKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_signed_pre_key_record_get_public_key(k, handle) });
    }

    func getPrivateKey() throws -> PrivateKey {
        return try invokeFnReturningPrivateKey(fn: { (k) in signal_signed_pre_key_record_get_private_key(k, handle) });
    }

    func getSignature() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_signed_pre_key_record_get_signature(handle,b,bl) });
    }
}
