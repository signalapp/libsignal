//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi

public class SenderKeyName: ClonableHandleOwner {
    internal override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_sender_key_name_destroy(handle)
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_sender_key_name_clone(&newHandle, currentHandle)
    }

    public init(groupName: String, senderName: String, deviceId: UInt32) throws {
        var handle: OpaquePointer?
        try checkError(signal_sender_key_name_new(&handle, groupName, senderName, deviceId))
        super.init(owned: handle!)
    }

    public init(groupName: String, sender: ProtocolAddress) throws {
        var handle: OpaquePointer?
        try checkError(signal_sender_key_name_new(&handle, groupName, sender.name, sender.deviceId))
        super.init(owned: handle!)
    }

    internal override init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    public var groupId: String {
        return try! invokeFnReturningString {
            signal_sender_key_name_get_group_id(nativeHandle, $0)
        }
    }

    public var senderName: String {
        return try! invokeFnReturningString {
            signal_sender_key_name_get_sender_name(nativeHandle, $0)
        }
    }

    public var senderDeviceId: UInt32 {
        return try! invokeFnReturningInteger {
            signal_sender_key_name_get_sender_device_id(nativeHandle, $0)
        }
    }
}

extension SenderKeyName: Hashable {
    public static func == (lhs: SenderKeyName, rhs: SenderKeyName) -> Bool {
        if lhs.senderDeviceId != rhs.senderDeviceId {
            return false
        }

        if lhs.senderName != rhs.senderName {
            return false
        }

        return lhs.groupId == rhs.groupId

    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.senderDeviceId)
        hasher.combine(self.senderName)
        hasher.combine(self.groupId)
    }
}
