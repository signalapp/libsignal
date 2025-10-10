//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi

public class ProtocolAddress: ClonableHandleOwner<SignalMutPointerProtocolAddress>, @unchecked Sendable {
    /// Creates an address in the Signal protocol.
    /// - Parameters:
    ///   - name: the identifier for the recipient, usually a ``ServiceId``.
    ///   - deviceId: the identifier for the device; must be in the range 1-127 inclusive
    ///
    /// - Throws: ``SignalError#invalidProtocolAddress(name:deviceId:message:)`` if the address is not valid.
    public convenience init(name: String, deviceId: UInt32) throws {
        let handle = try invokeFnReturningValueByPointer(.init()) {
            signal_address_new($0, name, deviceId)
        }
        self.init(owned: NonNull(handle)!)
    }

    /// Creates a ProtocolAddress using the **uppercase** string representation of a service ID, for backward compatibility.
    /// - Parameters:
    ///   - serviceId: the identifier for the recipient
    ///   - deviceId: the identifier for the device; must be in the range 1-127 inclusive
    ///
    /// - Throws: ``SignalError#invalidProtocolAddress(name:deviceId:message:)`` if the address is not valid.
    public convenience init(_ serviceId: ServiceId, deviceId: UInt32) {
        do {
            try self.init(name: serviceId.serviceIdUppercaseString, deviceId: deviceId)
        } catch {
            // `self.init` can't be put inside a closure, but we want the same error handling `failOnError` gives us.
            // So we rethrow the error here.
            failOnError { () -> Never in throw error }
        }
    }

    override internal class func cloneNativeHandle(
        _ newHandle: inout SignalMutPointerProtocolAddress,
        currentHandle: SignalConstPointerProtocolAddress
    ) -> SignalFfiErrorRef? {
        return signal_address_clone(&newHandle, currentHandle)
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerProtocolAddress>
    ) -> SignalFfiErrorRef? {
        return signal_address_destroy(handle.pointer)
    }

    public var name: String {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningString {
                    signal_address_get_name($0, nativeHandle.const())
                }
            }
        }
    }

    /// Returns a ServiceId if this address contains a valid ServiceId, `nil` otherwise.
    ///
    /// In a future release ProtocolAddresses will *only* support ServiceIds.
    public var serviceId: ServiceId! {
        return try? ServiceId.parseFrom(serviceIdString: self.name)
    }

    public var deviceId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_address_get_device_id($0, nativeHandle.const())
                }
            }
        }
    }
}

extension ProtocolAddress: CustomDebugStringConvertible {
    public var debugDescription: String {
        return "\(self.name).\(self.deviceId)"
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

extension SignalMutPointerProtocolAddress: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerProtocolAddress

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerProtocolAddress: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
