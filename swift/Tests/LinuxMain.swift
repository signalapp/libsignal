//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
@testable import SignalClientTests

XCTMain([
    testCase(ClonableHandleOwnerTests.allTests),
    testCase(PublicAPITests.allTests),
    testCase(SessionTests.allTests),
    testCase(ZKGroupTests.allTests),
])
