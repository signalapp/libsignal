//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class UnauthCredentialsServiceTests: UnauthChatServiceTestBase<any UnauthCredentialsService> {
    override class var selector: SelectorCheck { .credentials }

    func testCheckSvrCredentials() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_CheckSvrCredentialsTests(),
            invoke: { api, args in
                try await api.checkSvrCredentials(
                    number: args.number,
                    credentials: args.passwords,
                )
            },
            check: { expected, actual in
                XCTAssertEqual(Dictionary(uniqueKeysWithValues: expected), try actual.get())
            }
        )
    }
}

#endif
