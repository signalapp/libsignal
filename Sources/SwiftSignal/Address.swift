import SignalFfi
import Foundation

class ProtocolAddress: ClonableHandleOwner {
    init(name: String, device_id: UInt32) throws {
        var handle: OpaquePointer?
        try CheckError(signal_address_new(&handle,
                                          name,
                                          device_id))
        super.init(owned: handle!)
    }

    internal override init(unowned handle: OpaquePointer?) {
        super.init(unowned: handle)
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_address_clone(&newHandle, currentHandle)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_address_destroy(handle)
    }

    var name: String {
        return try! invokeFnReturningString(fn: { (b) in signal_address_get_name(nativeHandle(), b) })
    }

    var deviceId: UInt32 {
        return try! invokeFnReturningInteger(fn: { (i) in signal_address_get_device_id(nativeHandle(), i) })
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
