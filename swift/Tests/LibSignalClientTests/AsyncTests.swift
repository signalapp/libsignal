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

    func testInvokeAsyncHandleTypes() async throws {
        do {
            let value = UInt8(44)
            let handle: OpaquePointer = try await invokeAsyncFunction {
                signal_testing_future_produces_pointer_type($0, $1, OpaquePointer(bitPattern: -1), value)
            }
            defer { signal_testing_handle_type_destroy(handle) }
            XCTAssertEqual(
                try invokeFnReturningInteger { result in
                    signal_testing_testing_handle_type_get_value(result, handle)
                }, value)
        }

        do {
            let value = "into the future"
            let otherHandle: OpaquePointer = try await invokeAsyncFunction {
                signal_testing_future_produces_other_pointer_type($0, $1, OpaquePointer(bitPattern: -1), value)
            }
            defer { signal_other_testing_handle_type_destroy(otherHandle) }

            XCTAssertEqual(
                try invokeFnReturningString { result in
                    signal_testing_other_testing_handle_type_get_value(result, otherHandle)
                }, value)
        }
    }
}

#endif
