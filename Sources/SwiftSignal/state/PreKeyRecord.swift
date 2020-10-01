import SignalFfi
import Foundation

class PreKeyRecord {
    private var handle: OpaquePointer?

    deinit {
        signal_pre_key_record_destroy(handle)
    }

    init(bytes: [UInt8]) throws {
        try CheckError(signal_pre_key_record_deserialize(&handle, bytes, bytes.count))
    }

    internal init(clone_from: OpaquePointer?) throws {
        try CheckError(signal_pre_key_record_clone(&handle, clone_from));
    }

    init(id: UInt32,
         pub_key: PublicKey,
         priv_key: PrivateKey) throws {
        try CheckError(signal_pre_key_record_new(&handle, id, pub_key.nativeHandle(), priv_key.nativeHandle()))
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_pre_key_record_serialize(handle,b,bl) })
    }

    func getId() throws -> UInt32 {
        return try invokeFnReturningUInt32(fn: { (i) in signal_pre_key_record_get_id(handle, i) })
    }

    func getPublicKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_pre_key_record_get_public_key(k, handle) })
    }

    func getPrivateKey() throws -> PrivateKey {
        return try invokeFnReturningPrivateKey(fn: { (k) in signal_pre_key_record_get_private_key(k, handle) })
    }

    func leakNativeHandle() -> OpaquePointer? {
        let save = handle
        handle = nil
        return save
    }
}
