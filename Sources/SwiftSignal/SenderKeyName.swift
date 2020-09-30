import SignalFfi
import Foundation

class SenderKeyName {
    private var handle: OpaquePointer?;

    init(group_name: String, sender_name: String, device_id: UInt32) throws {
        try CheckError(signal_sender_key_name_new(&handle, group_name, sender_name, device_id))
    }

    init(group_name: String, sender: ProtocolAddress) throws {
        try CheckError(signal_sender_key_name_new(&handle, group_name, sender.getName(), sender.getDeviceId()))
    }

    internal init(raw_ptr: OpaquePointer?) {
        handle = raw_ptr
    }

    internal init(clone_from: OpaquePointer?) throws {
        try CheckError(signal_sender_key_name_clone(&handle, clone_from))
    }

    deinit {
        signal_sender_key_name_destroy(handle)
    }

    func getGroupId() throws -> String {
        return try invokeFnReturningString(fn: { (b) in signal_sender_key_name_get_group_id(handle, b) })
    }

    func getSenderName() throws -> String {
        return try invokeFnReturningString(fn: { (b) in signal_sender_key_name_get_sender_name(handle, b) })
    }

    func getSenderDeviceId() throws -> UInt32 {
        return try invokeFnReturningUInt32(fn: { (i) in signal_sender_key_name_get_sender_device_id(handle, i) })
    }

    internal func nativeHandle() -> OpaquePointer? {
        return handle
    }
}

extension SenderKeyName: Hashable {
    static func == (lhs: SenderKeyName, rhs: SenderKeyName) -> Bool {
        let lhsDeviceId = try! lhs.getSenderDeviceId()
        let rhsDeviceId = try! rhs.getSenderDeviceId()

        if lhsDeviceId != rhsDeviceId {
            return false
        }

        let lhsName = try! lhs.getSenderName()
        let rhsName = try! rhs.getSenderName()

        if lhsName != rhsName {
            return false
        }

        let lhsGroupId = try! lhs.getGroupId()
        let rhsGroupId = try! rhs.getGroupId()
        return lhsGroupId == rhsGroupId

    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(try! getGroupId())
        hasher.combine(try! getSenderName())
        hasher.combine(try! getSenderDeviceId())
    }
}
