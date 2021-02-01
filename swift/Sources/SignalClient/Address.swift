//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi

public class ProtocolAddress: ClonableHandleOwner {
    public init(name: String, deviceId: UInt32) throws {
        var handle: OpaquePointer?
        try checkError(signal_address_new(&handle,
                                          name,
                                          deviceId))
        super.init(owned: handle!)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    internal override init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_address_clone(&newHandle, currentHandle)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_address_destroy(handle)
    }

    public var name: String {
        return failOnError {
            try invokeFnReturningString {
                signal_address_get_name($0, nativeHandle)
            }
        }
    }

    public var deviceId: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_address_get_device_id($0, nativeHandle)
            }
        }
    }
}

extension ProtocolAddress: Hashable {
    public static func == (lhs: ProtocolAddress, rhs: ProtocolAddress) -> Bool {
        if lhs.deviceId != rhs.deviceId {
            return false
        }

        return lhs.name == rhs.name
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.name)
        hasher.combine(self.deviceId)
    }
}
