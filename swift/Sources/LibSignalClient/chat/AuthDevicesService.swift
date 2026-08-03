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
    /// Remove a linked device from the current account.
    ///
    /// Linked devices may only remove themselves, and primary devices may
    /// remove any device other than themselves; the server rejects anything
    /// else as a programmer error.
    ///
    /// Removing a device ID that is not on the account also succeeds, so a
    /// caller retrying a removal sees the same result as the original call.
    /// This is not true idempotency, though: device IDs are small and get
    /// reused, so if a new device is linked and assigned ``deviceId`` between
    /// two calls, the second call removes that new device.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func removeDevice(deviceId: DeviceId) async throws
    /// Set the name of the given device ID to the provided encrypted name.
    ///
    /// - Parameters:
    ///   - encryptedDeviceName: Must be between 1 and 225 bytes long
    /// - Throws:
    ///   - ``SignalError/deviceIdNotFound(_:)`` if ``deviceId`` could not be found
    ///   - the standard Signal network errors
    func setDeviceName(deviceId: DeviceId, encryptedDeviceName: Data) async throws
    /// Sets the APNs device token the server should use to send new message
    /// notifications to the authenticated device.
    ///
    /// - Parameters:
    ///   - apnsToken: Must not be empty
    /// - Throws:
    ///   - the standard Signal network errors
    func setPushToken(apns apnsToken: String) async throws
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

    public func removeDevice(deviceId: DeviceId) async throws {
        return try await NativeNice.AuthenticatedChatConnection_remove_device(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            deviceId: deviceId
        )
    }

    public func setDeviceName(deviceId: DeviceId, encryptedDeviceName: Data) async throws {
        return try await NativeNice.AuthenticatedChatConnection_set_device_name(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            deviceId: deviceId,
            encryptedName: encryptedDeviceName
        )
    }

    public func setPushToken(apns apnsToken: String) async throws {
        return try await NativeNice.AuthenticatedChatConnection_set_push_token_apns(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            apnsToken: apnsToken
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
