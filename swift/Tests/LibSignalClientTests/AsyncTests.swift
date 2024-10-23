//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

@testable import LibSignalClient
import SignalFfi
import XCTest

extension SignalCPromiseTestingHandleType: LibSignalClient.PromiseStruct {
    public typealias Result = OpaquePointer
}

extension SignalCPromiseOtherTestingHandleType: LibSignalClient.PromiseStruct {
    public typealias Result = OpaquePointer
}

final class AsyncTests: TestCaseBase {
    func testSuccess() async throws {
        let result: Int32 = try await invokeAsyncFunction {
            signal_testing_future_success($0, OpaquePointer(bitPattern: -1), 21)
        }
        XCTAssertEqual(42, result)
    }

    func testFailure() async throws {
        do {
            let _: Int32 = try await invokeAsyncFunction {
                signal_testing_future_failure($0, OpaquePointer(bitPattern: -1), 21)
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
                signal_testing_future_produces_pointer_type($0, OpaquePointer(bitPattern: -1), value)
            }
            defer { signal_testing_handle_type_destroy(handle) }
            XCTAssertEqual(
                try invokeFnReturningInteger { result in
                    signal_testing_testing_handle_type_get_value(result, handle)
                }, value
            )
        }

        do {
            let value = "into the future"
            let otherHandle: OpaquePointer = try await invokeAsyncFunction {
                signal_testing_future_produces_other_pointer_type($0, OpaquePointer(bitPattern: -1), value)
            }
            defer { signal_other_testing_handle_type_destroy(otherHandle) }

            XCTAssertEqual(
                try invokeFnReturningString { result in
                    signal_testing_other_testing_handle_type_get_value(result, otherHandle)
                }, value
            )
        }
    }

    func testTokioCancellation() async throws {
        let asyncContext = TokioAsyncContext()

        // We can replace this with AsyncStream.makeStream(...) when we update our builder.
        var _continuation: AsyncStream<Int>.Continuation!
        let completionStream = AsyncStream<Int> { _continuation = $0 }
        let continuation = _continuation!

        let makeTask = { (id: Int) in
            Task {
                defer {
                    // Do this unconditionally so that the outer test procedure doesn't get stuck.
                    continuation.yield(id)
                }
                do {
                    _ = try await asyncContext.invokeAsyncFunction { promise, asyncContext in
                        signal_testing_only_completes_by_cancellation(promise, asyncContext)
                    }
                } catch is CancellationError {
                    // Okay, expected.
                } catch {
                    XCTFail("incorrect error: \(error)")
                }
            }
        }
        let task1 = makeTask(1)
        let task2 = makeTask(2)

        var completionIter = completionStream.makeAsyncIterator()

        // Complete the tasks in opposite order of starting them,
        // to make it less likely to get this result by accident.
        // This is not a rigorous test, only a simple exercise of the feature.
        task2.cancel()
        let firstCompletionId = await completionIter.next()
        XCTAssertEqual(firstCompletionId, 2)

        task1.cancel()
        let secondCompletionId = await completionIter.next()
        XCTAssertEqual(secondCompletionId, 1)
    }
}

#endif
