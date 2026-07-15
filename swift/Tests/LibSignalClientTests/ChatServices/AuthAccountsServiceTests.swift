//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthAccountsServiceTests: AuthChatServiceTestBase<any AuthAccountsService> {
    override class var selector: SelectorCheck { .accounts }

    func testSetRegistrationLock() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetRegistrationLockTests(),
            invoke: { api, svrKey in
                try await api.setRegistrationLock(SvrKey(contents: svrKey))
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }

    func testSetDiscoverableByPhoneNumber() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetDiscoverableByPhoneNumberTests(),
            invoke: { api, discoverable in
                try await api.setDiscoverableByPhoneNumber(discoverable)
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }
}

#endif
