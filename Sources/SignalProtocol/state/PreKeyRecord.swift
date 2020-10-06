import SignalFfi

class PreKeyRecord: ClonableHandleOwner {
    private var handle: OpaquePointer?

    override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_pre_key_record_destroy(handle)
    }

    override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_pre_key_record_clone(&newHandle, currentHandle)
    }

    init(bytes: [UInt8]) throws {
        var handle: OpaquePointer?
        try checkError(signal_pre_key_record_deserialize(&handle, bytes, bytes.count))
        super.init(owned: handle!)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    init(id: UInt32,
         publicKey: PublicKey,
         privateKey: PrivateKey) throws {
        var handle: OpaquePointer?
        try checkError(signal_pre_key_record_new(&handle, id, publicKey.nativeHandle, privateKey.nativeHandle))
        super.init(owned: handle!)
    }

    init(id: UInt32, privateKey: PrivateKey) throws {
        let publicKey = try privateKey.publicKey()
        var handle: OpaquePointer?
        try checkError(signal_pre_key_record_new(&handle, id, publicKey.nativeHandle, privateKey.nativeHandle))
        super.init(owned: handle!)
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_pre_key_record_serialize(handle, $0, $1)
        }
    }

    func id() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_pre_key_record_get_id(handle, $0)
        }
    }

    func publicKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey {
            signal_pre_key_record_get_public_key($0, handle)
        }
    }

    func privateKey() throws -> PrivateKey {
        return try invokeFnReturningPrivateKey {
            signal_pre_key_record_get_private_key($0, handle)
        }
    }
}
