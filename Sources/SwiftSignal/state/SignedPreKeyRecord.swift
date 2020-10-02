import SignalFfi
import Foundation

class SignedPreKeyRecord {
    private var handle: OpaquePointer?

    deinit {
        signal_signed_pre_key_record_destroy(handle)
    }

    init(bytes: [UInt8]) throws {
        try CheckError(signal_signed_pre_key_record_deserialize(&handle, bytes, bytes.count))
    }

    init(id: UInt32,
         timestamp: UInt64,
         priv_key: PrivateKey,
         signature: [UInt8]) throws {
        let pub_key = try priv_key.getPublicKey();
        try CheckError(signal_signed_pre_key_record_new(&handle, id, timestamp,
                                                        pub_key.nativeHandle(), priv_key.nativeHandle(),
                                                        signature, signature.count));
    }

    internal init(clone_from: OpaquePointer?) throws {
        try CheckError(signal_signed_pre_key_record_clone(&handle, clone_from));
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_signed_pre_key_record_serialize(handle,b,bl) })
    }

    func getId() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_signed_pre_key_record_get_id(handle, i) })
    }

    func getTimestamp() throws -> UInt64 {
        return try invokeFnReturningInteger(fn: { (i) in signal_signed_pre_key_record_get_timestamp(handle, i) })
    }

    func getPublicKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_signed_pre_key_record_get_public_key(k, handle) })
    }

    func getPrivateKey() throws -> PrivateKey {
        return try invokeFnReturningPrivateKey(fn: { (k) in signal_signed_pre_key_record_get_private_key(k, handle) })
    }

    func getSignature() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_signed_pre_key_record_get_signature(handle,b,bl) })
    }

    internal func leakNativeHandle() -> OpaquePointer? {
        let save = handle;
        handle = nil;
        return save;
    }
}
