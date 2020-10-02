import SignalFfi
import Foundation

class ProtocolAddress {
    private var handle: OpaquePointer?

    internal func nativeHandle() -> OpaquePointer? {
        return handle
    }

    init(name: String, device_id: UInt32) throws {
        try CheckError(signal_address_new(&handle,
                                          name,
                                          device_id))
    }

    internal init(clone_from: OpaquePointer?) throws {
        try CheckError(signal_address_clone(&handle, clone_from))
    }

    deinit {
        signal_address_destroy(handle)
    }

    func getName() throws -> String {
        return try invokeFnReturningString(fn: { (b) in signal_address_get_name(handle, b) })
    }

    func getDeviceId() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_address_get_device_id(handle, i) })
    }
}

extension ProtocolAddress: Hashable {
    static func == (lhs: ProtocolAddress, rhs: ProtocolAddress) -> Bool {
        let lhsDeviceId = try! lhs.getDeviceId()
        let rhsDeviceId = try! rhs.getDeviceId()

        if lhsDeviceId != rhsDeviceId {
            return false
        }

        let lhsSenderName = try! lhs.getName()
        let rhsSenderName = try! rhs.getName()
        return lhsSenderName == rhsSenderName
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(try! getName())
        hasher.combine(try! getDeviceId())
    }
}
