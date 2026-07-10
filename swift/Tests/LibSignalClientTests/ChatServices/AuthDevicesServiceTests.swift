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

    func testSetPushTokenApns() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetPushTokenApnsTests(),
            invoke: { api, apnsToken in
                try await api.setPushToken(apns: apnsToken)
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }

    func testRemoveDevice() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_RemoveDeviceTests(),
            invoke: { api, args in
                try await api.removeDevice(deviceId: DeviceId(validating: args.id)!)
            },
            check: { expected, actual in
                switch expected {
                case .success:
                    try actual.get()
                }
            }
        )
    }

    func testGetDevices() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetDevicesTests(),
            invoke: { api, _ in
                try await api.getDevices()
            },
            check: { expected, actual in
                XCTAssertEqual(expected.devices.map { LinkedDevice.fromInternal($0) }, try actual.get())
            }
        )
    }

    func testClearPushToken() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_ClearPushTokenTests(),
            invoke: { api, _ in
                try await api.clearPushToken()
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }
}

#endif
