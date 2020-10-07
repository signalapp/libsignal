import SignalFfi

class PublicKey: ClonableHandleOwner {
    init(_ bytes: [UInt8]) throws {
        var handle: OpaquePointer?
        try checkError(signal_publickey_deserialize(&handle, bytes, bytes.count))
        super.init(owned: handle!)
    }

    internal override init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_publickey_destroy(handle)
    }

    override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_publickey_clone(&newHandle, currentHandle)
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_publickey_serialize(nativeHandle, $0, $1)
        }
    }

    func verifySignature(message: [UInt8], signature: [UInt8]) throws -> Bool {
        var result: Bool = false
        try checkError(signal_publickey_verify(nativeHandle, &result, message, message.count, signature, signature.count))
        return result
    }

    func compare(_ other: PublicKey) -> Int32 {
        var result: Int32 = 0
        try! checkError(signal_publickey_compare(&result, nativeHandle, other.nativeHandle))
        return result
    }
}

extension PublicKey: Equatable {
    static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.compare(rhs) == 0
    }
}

extension PublicKey: Comparable {
    static func < (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.compare(rhs) < 0
    }
}
