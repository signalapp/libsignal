//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthDevicesServiceTests: AuthChatServiceTestBase<any AuthDevicesService> {
    override class var selector: SelectorCheck { .devices }

    func testSetDeviceName() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetDeviceNameTests(),
            invoke: { api, args in
                try await api.setDeviceName(
                    deviceId: DeviceId(validating: args.id)!,
                    encryptedDeviceName: args.encryptedName
                )
            },
            check: { expected, actual in
                switch expected {
                case .success:
                    try actual.get()
                case .deviceNotFound:
                    do {
                        try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.deviceIdNotFound(_) {}
                }
            }
        )
    }
}

#endif
