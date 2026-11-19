//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class UnauthKeysServiceTests: UnauthChatServiceTestBase<any UnauthKeysService> {
    override class var selector: SelectorCheck { .keys }

    func testGetPreKeys() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetPreKeysTests(),
            invoke: { api, request in
                let auth: UserBasedAuthorization =
                    switch request.auth {
                    case .accessKey(let key):
                        .accessKey(key)
                    case .groupSendToken(let token):
                        .groupSend(try GroupSendFullToken(contents: token))
                    case .unrestricted:
                        .unrestrictedUnauthenticatedAccess
                    }
                let device: DeviceSpecifier =
                    if request.deviceId < 0 {
                        .allDevices
                    } else {
                        .specificDevice(DeviceId(validating: UInt32(request.deviceId))!)
                    }
                return try await api.getPreKeys(for: request.target, device: device, auth: auth)
            },
            check: { expected, actual in
                switch (expected, actual) {
                case (.success(let identityKey, let bundleCount), .success(let result)):
                    XCTAssertEqual(identityKey, result.0.serialize())
                    XCTAssertEqual(Int(bundleCount), result.1.count)
                case (.notFound, .failure(SignalError.serviceIdNotFound(_))),
                    (.unauthorized, .failure(SignalError.requestUnauthorized(_))),
                    (.unexpected, .failure):
                    break
                case (_, .success):
                    XCTFail("expected getPreKeys to fail")
                case (_, .failure(let error)):
                    XCTFail("unexpected getPreKeys error: \(error)")
                }
            },
        )
    }
}

#endif
