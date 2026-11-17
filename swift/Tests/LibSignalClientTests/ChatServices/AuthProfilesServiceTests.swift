//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthProfilesServiceTests: AuthChatServiceTestBase<any AuthProfilesService> {
    override class var selector: SelectorCheck { .profiles }

    func testGetAvatarUploadFormLegacy() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetAvatarUploadFormLegacyTests(),
            invoke: { api, args in
                try await api.getAvatarUploadFormLegacy(
                    aci: args.aci,
                    profileKey: args.profileKey,
                )
            },
            check: { expected, actual in
                XCTAssertEqual(expected, try actual.get())
            }
        )
    }
}

#endif
