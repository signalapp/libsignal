import SignalFfi

class SignedPreKeyRecord: ClonableHandleOwner {
    override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_signed_pre_key_record_destroy(handle)
    }

    override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_signed_pre_key_record_clone(&newHandle, currentHandle)
    }

    init(bytes: [UInt8]) throws {
        var handle: OpaquePointer?
        try checkError(signal_signed_pre_key_record_deserialize(&handle, bytes, bytes.count))
        super.init(owned: handle!)
    }

    init(id: UInt32,
         timestamp: UInt64,
         privateKey: PrivateKey,
         signature: [UInt8]) throws {
        let pub_key = try privateKey.publicKey()
        var handle: OpaquePointer?
        try checkError(signal_signed_pre_key_record_new(&handle, id, timestamp,
                                                        pub_key.nativeHandle, privateKey.nativeHandle,
                                                        signature, signature.count));
        super.init(owned: handle!)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_signed_pre_key_record_serialize(nativeHandle,b,bl) })
    }

    func id() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_signed_pre_key_record_get_id(nativeHandle, i) })
    }

    func timestamp() throws -> UInt64 {
        return try invokeFnReturningInteger(fn: { (i) in signal_signed_pre_key_record_get_timestamp(nativeHandle, i) })
    }

    func publicKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_signed_pre_key_record_get_public_key(k, nativeHandle) })
    }

    func privateKey() throws -> PrivateKey {
        return try invokeFnReturningPrivateKey(fn: { (k) in signal_signed_pre_key_record_get_private_key(k, nativeHandle) })
    }

    func signature() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_signed_pre_key_record_get_signature(nativeHandle,b,bl) })
    }
}
