import SignalFfi

class ProtocolAddress: ClonableHandleOwner {
    init(name: String, device_id: UInt32) throws {
        var handle: OpaquePointer?
        try checkError(signal_address_new(&handle,
                                          name,
                                          device_id))
        super.init(owned: handle!)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_address_clone(&newHandle, currentHandle)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_address_destroy(handle)
    }

    var name: String {
        return try! invokeFnReturningString {
            signal_address_get_name(nativeHandle, $0)
        }
    }

    var deviceId: UInt32 {
        return try! invokeFnReturningInteger {
            signal_address_get_device_id(nativeHandle, $0)
        }
    }
}

extension ProtocolAddress: Hashable {
    static func == (lhs: ProtocolAddress, rhs: ProtocolAddress) -> Bool {
        if lhs.deviceId != rhs.deviceId {
            return false
        }

        return lhs.name == rhs.name
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(self.name)
        hasher.combine(self.deviceId)
    }
}
