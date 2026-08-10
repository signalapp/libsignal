//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class UnauthCallQualityServiceTests: UnauthChatServiceTestBase<any UnauthCallQualityService> {
    override class var selector: SelectorCheck { .callQuality }

    func testSubmitCallQualitySurvey() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SubmitCallQualitySurveyTests(),
            invoke: { api, args in
                try await api.submitCallQualitySurvey(
                    survey: args,
                )
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }
}

#endif
