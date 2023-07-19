//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi

public class ProtocolAddress: ClonableHandleOwner {
    public convenience init(name: String, deviceId: UInt32) throws {
        var handle: OpaquePointer?
        try checkError(signal_address_new(&handle,
                                          name,
                                          deviceId))
        self.init(owned: handle!)
    }

    /// Creates a ProtocolAddress using the **uppercase** string representation of a service ID, for backward compatibility.
    public convenience init(_ serviceId: ServiceId, deviceId: UInt32) {
        do {
            try self.init(name: serviceId.serviceIdUppercaseString, deviceId: deviceId)
        } catch {
            // `self.init` can't be put inside a closure, but we want the same error handling `failOnError` gives us.
            // So we rethrow the error here.
            failOnError { () -> Never in throw error }
        }
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_address_clone(&newHandle, currentHandle)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_address_destroy(handle)
    }

    public var name: String {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningString {
                    signal_address_get_name($0, nativeHandle)
                }
            }
        }
    }

    /// Returns a ServiceId if this address contains a valid ServiceId, `nil` otherwise.
    ///
    /// In a future release ProtocolAddresses will *only* support ServiceIds.
    public var serviceId: ServiceId! {
        return try? ServiceId.parseFrom(serviceIdString: name)
    }

    public var deviceId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_address_get_device_id($0, nativeHandle)
                }
            }
        }
    }
}

extension ProtocolAddress: CustomDebugStringConvertible {
    public var debugDescription: String {
        return "\(name).\(deviceId)"
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
