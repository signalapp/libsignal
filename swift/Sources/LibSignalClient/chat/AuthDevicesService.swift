//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public struct LinkedDevice: Equatable {
    /// The identifier for the device within an account.
    public let id: DeviceId
    /// A sequence of bytes that encodes an encrypted human-readable name for
    /// this device.
    public let encryptedName: Data
    /// The approximate time at which this device last connected to the server.
    public let lastSeen: Date
    /// The registration ID of the given device.
    public let registrationId: UInt16
    /// A sequence of bytes that encodes the time,
    /// in milliseconds since the epoch, at which this device was
    /// attached to its parent account.
    public let createdAtCiphertext: Data

    public init(
        id: DeviceId,
        encryptedName: Data,
        lastSeen: Date,
        registrationId: UInt16,
        createdAtCiphertext: Data
    ) {
        self.id = id
        self.encryptedName = encryptedName
        self.lastSeen = lastSeen
        self.registrationId = registrationId
        self.createdAtCiphertext = createdAtCiphertext
    }

    internal static func fromInternal(_ it: LinkedDeviceInternal) -> LinkedDevice {
        LinkedDevice(
            id: it.id,
            encryptedName: it.encryptedName,
            lastSeen: it.lastSeen,
            registrationId: it.registrationId,
            createdAtCiphertext: it.createdAtCiphertext,
        )
    }
}

public protocol AuthDevicesService: Sendable {
    /// List the devices associated with the current account.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func getDevices() async throws -> [LinkedDevice]
    /// Set the name of the given device ID to the provided encrypted name.
    ///
    /// - Parameters:
    ///   - encryptedDeviceName: Must be between 1 and 225 bytes long
    /// - Throws:
    ///   - ``SignalError/deviceIdNotFound(_:)`` if ``deviceId`` could not be found
    ///   - the standard Signal network errors
    func setDeviceName(deviceId: DeviceId, encryptedDeviceName: Data) async throws
    /// Remove any push tokens associated with the current device.
    ///
    /// After this call, the server will assume the current device will
    /// periodically poll for new messages.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func clearPushToken() async throws
}

extension AuthenticatedChatConnection: AuthDevicesService {

    public func getDevices() async throws -> [LinkedDevice] {
        return try await NativeNice.AuthenticatedChatConnection_get_devices(
            asyncContext: self.tokioAsyncContext,
            chat: self,
        ).map { LinkedDevice.fromInternal($0) }
    }

    public func setDeviceName(deviceId: DeviceId, encryptedDeviceName: Data) async throws {
        return try await NativeNice.AuthenticatedChatConnection_set_device_name(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            deviceId: deviceId.int32Value,
            encryptedName: encryptedDeviceName
        )
    }

    public func clearPushToken() async throws {
        return try await NativeNice.AuthenticatedChatConnection_clear_push_token(
            asyncContext: self.tokioAsyncContext,
            chat: self,
        )
    }

}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthDevicesService> {
    public static var devices: Self { .init() }
}
