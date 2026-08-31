//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthPaymentsServiceTests: AuthChatServiceTestBase<any AuthPaymentsService> {
    override class var selector: SelectorCheck { .payments }

    func testGetCurrencyConversions() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetCurrencyConversionsTests(),
            invoke: { api, _ in
                try await api.getCurrencyConversions()
            },
            check: { expected, actual in
                XCTAssertEqual(try actual.get(), CurrencyConversions(fromInternal: expected))
            }
        )
    }
}

#endif
