//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
@testable import LibSignalClient
import SignalFfi
import XCTest

final class NativeTests: XCTestCase {
// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)
    func testTestingFnsAreAvailable() async throws {
        let output = try invokeFnReturningInteger(fn: SignalFfi.signal_test_only_fn_returns_123)
        XCTAssertEqual(output, 123)
    }
#endif
}
