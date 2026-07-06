//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public protocol AuthDevicesService: Sendable {
    /// Set the name of the given device ID to the provided encrypted name.
    ///
    /// - Parameters:
    ///   - encryptedDeviceName: Must be between 1 and 225 bytes long
    /// - Throws:
    ///   - ``SignalError/deviceIdNotFound(_:)`` if ``deviceId`` could not be found
    ///   - the standard Signal network errors
    func setDeviceName(deviceId: DeviceId, encryptedDeviceName: Data) async throws
}

extension AuthenticatedChatConnection: AuthDevicesService {
    public func setDeviceName(deviceId: DeviceId, encryptedDeviceName: Data) async throws {
        return try await NativeNice.AuthenticatedChatConnection_set_device_name(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            deviceId: deviceId.int32Value,
            encryptedName: encryptedDeviceName
        )
    }

}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthDevicesService> {
    public static var devices: Self { .init() }
}
