//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthRemoteConfigurationServiceTests: AuthChatServiceTestBase<any AuthRemoteConfigurationService> {
    override class var selector: SelectorCheck { .remoteConfiguration }

    func testGetBadges() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetBadgesTests(),
            invoke: { api, args in
                try await api.getBadges(
                    etag: args,
                )
            },
            check: { expected, actual in
                XCTAssertEqual(expected, try actual.get())
            }
        )
    }
}

#endif
