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
        let publicKey = try privateKey.publicKey()
        var handle: OpaquePointer?
        try checkError(signal_signed_pre_key_record_new(&handle, id, timestamp,
                                                        publicKey.nativeHandle, privateKey.nativeHandle,
                                                        signature, signature.count));
        super.init(owned: handle!)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_signed_pre_key_record_serialize(nativeHandle, $0, $1)
        }
    }

    func id() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_signed_pre_key_record_get_id(nativeHandle, $0)
        }
    }

    func timestamp() throws -> UInt64 {
        return try invokeFnReturningInteger {
            signal_signed_pre_key_record_get_timestamp(nativeHandle, $0)
        }
    }

    func publicKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey {
            signal_signed_pre_key_record_get_public_key($0, nativeHandle)
        }
    }

    func privateKey() throws -> PrivateKey {
        return try invokeFnReturningPrivateKey {
            signal_signed_pre_key_record_get_private_key($0, nativeHandle)
        }
    }

    func signature() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_signed_pre_key_record_get_signature(nativeHandle, $0, $1)
        }
    }
}
