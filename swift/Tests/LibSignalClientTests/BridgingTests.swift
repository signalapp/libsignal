//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

import XCTest
@testable import LibSignalClient
import SignalFfi

private func fakeAsyncRuntime() -> OpaquePointer! {
    OpaquePointer(bitPattern: -1)
}

private func invokeFnIgnoringResult<T>(fn: (UnsafeMutablePointer<T>?) -> SignalFfiErrorRef?) throws {
    // Swift doesn't have a way to declare uninitialized local variables, so we have to allocate one on the heap.
    // This will almost certainly get stack-promoted, but since this is a test it doesn't really matter anyway.
    let output = UnsafeMutablePointer<T>.allocate(capacity: 1)
    defer { output.deallocate() }
    try checkError(fn(output))
}

final class BridgingTests: XCTestCase {
    func testErrorOnBorrow() async throws {
        do {
            try checkError(signal_testing_error_on_borrow_sync(nil))
            XCTFail("should have failed")
        } catch SignalError.invalidArgument(_) {
            // good
        }

        do {
            try checkError(signal_testing_error_on_borrow_async(nil))
            XCTFail("should have failed")
        } catch SignalError.invalidArgument(_) {
            // good
        }

        do {
            _ = try await invokeAsyncFunction(returning: Bool.self) {
                signal_testing_error_on_borrow_io($0, $1, fakeAsyncRuntime(), nil)
            }
            XCTFail("should have failed")
        } catch SignalError.invalidArgument(_) {
            // good
        }
    }

    func testPanicOnBorrow() async throws {
        do {
            try checkError(signal_testing_panic_on_borrow_sync(nil))
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }

        do {
            try checkError(signal_testing_panic_on_borrow_async(nil))
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }

        do {
            _ = try await invokeAsyncFunction(returning: Bool.self) {
                signal_testing_panic_on_borrow_io($0, $1, fakeAsyncRuntime(), nil)
            }
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }
    }

    func testPanicOnLoad() async throws {
        do {
            try checkError(signal_testing_panic_on_load_sync(nil, nil))
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }

        do {
            try checkError(signal_testing_panic_on_load_async(nil, nil))
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }

        do {
            _ = try await invokeAsyncFunction(returning: Bool.self) {
                signal_testing_panic_on_load_io($0, $1, fakeAsyncRuntime(), nil, nil)
            }
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }
    }

    func testPanicInBody() async throws {
        do {
            try checkError(signal_testing_panic_in_body_sync(nil))
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }

        do {
            try checkError(signal_testing_panic_in_body_async(nil))
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }

        do {
            _ = try await invokeAsyncFunction(returning: Bool.self) {
                signal_testing_panic_in_body_io($0, $1, fakeAsyncRuntime(), nil)
            }
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }
    }

    func testErrorOnReturn() async throws {
        do {
            try invokeFnIgnoringResult { signal_testing_error_on_return_sync($0, nil) }
            XCTFail("should have failed")
        } catch SignalError.invalidArgument(_) {
            // good
        }

        do {
            try invokeFnIgnoringResult { signal_testing_error_on_return_async($0, nil) }
            XCTFail("should have failed")
        } catch SignalError.invalidArgument(_) {
            // good
        }

        do {
            _ = try await invokeAsyncFunction(returning: UnsafeRawPointer.self) {
                signal_testing_error_on_return_io($0, $1, fakeAsyncRuntime(), nil)
            }
            XCTFail("should have failed")
        } catch SignalError.invalidArgument(_) {
            // good
        }
    }

    func testPanicOnReturn() async throws {
        do {
            try invokeFnIgnoringResult { signal_testing_panic_on_return_sync($0, nil) }
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }

        do {
            try invokeFnIgnoringResult { signal_testing_panic_on_return_async($0, nil) }
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }

        do {
            _ = try await invokeAsyncFunction(returning: UnsafeRawPointer.self) {
                signal_testing_panic_on_return_io($0, $1, fakeAsyncRuntime(), nil)
            }
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }
    }
}

#endif
