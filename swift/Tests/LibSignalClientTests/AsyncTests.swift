//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

import XCTest
@testable import LibSignalClient
import SignalFfi

final class AsyncTests: XCTestCase {
    func testSuccess() async throws {
        let result: Int32 = try await invokeAsyncFunction {
            signal_testing_future_success($0, $1, OpaquePointer(bitPattern: -1), 21)
        }
        XCTAssertEqual(42, result)
    }

    func testFailure() async throws {
        do {
            let _: Int32 = try await invokeAsyncFunction {
                signal_testing_future_failure($0, $1, OpaquePointer(bitPattern: -1), 21)
            }
            XCTFail("should have failed")
        } catch SignalError.invalidArgument(_) {
            // good
        }
    }
}

#endif
