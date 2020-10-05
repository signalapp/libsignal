import SignalFfi
import Foundation

class SenderKeyName: ClonableHandleOwner {
    override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_sender_key_name_destroy(handle)
    }

    override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_sender_key_name_clone(&newHandle, currentHandle)
    }

    init(group_name: String, sender_name: String, device_id: UInt32) throws {
        var handle: OpaquePointer?
        try CheckError(signal_sender_key_name_new(&handle, group_name, sender_name, device_id))
        super.init(owned: handle!)
    }

    init(group_name: String, sender: ProtocolAddress) throws {
        var handle: OpaquePointer?
        try CheckError(signal_sender_key_name_new(&handle, group_name, sender.name, sender.deviceId))
        super.init(owned: handle!)
    }

    internal override init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    internal override init(unowned handle: OpaquePointer?) {
        super.init(unowned: handle)
    }

    var groupId: String {
        return try! invokeFnReturningString(fn: { (b) in signal_sender_key_name_get_group_id(nativeHandle, b) })
    }

    var senderName: String {
        return try! invokeFnReturningString(fn: { (b) in signal_sender_key_name_get_sender_name(nativeHandle, b) })
    }

    var senderDeviceId: UInt32 {
        return try! invokeFnReturningInteger(fn: { (i) in signal_sender_key_name_get_sender_device_id(nativeHandle, i) })
    }
}

extension SenderKeyName: Hashable {
    static func == (lhs: SenderKeyName, rhs: SenderKeyName) -> Bool {
        if lhs.senderDeviceId != rhs.senderDeviceId {
            return false
        }

        if lhs.senderName != rhs.senderName {
            return false
        }

        return lhs.groupId == rhs.groupId

    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(self.senderDeviceId)
        hasher.combine(self.senderName)
        hasher.combine(self.groupId)
    }
}
