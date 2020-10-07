import SignalFfi

class SessionRecord: ClonableHandleOwner {
    override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_session_record_destroy(handle)
    }

    override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_session_record_clone(&newHandle, currentHandle)
    }

    init(bytes: [UInt8]) throws {
        var handle: OpaquePointer?
        try checkError(signal_session_record_deserialize(&handle, bytes, bytes.count))
        super.init(owned: handle!)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_session_record_serialize(nativeHandle, $0, $1)
        }
    }
}
