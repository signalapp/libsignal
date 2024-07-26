//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
@testable import LibSignalClient
import SignalFfi
import XCTest

final class NativeTests: XCTestCase {
    func testTestingFnsAreAvailable() async throws {
        let output = try invokeFnReturningInteger(fn: SignalFfi.signal_test_only_fn_returns_123)
        XCTAssertEqual(output, 123)
    }
}
