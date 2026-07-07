//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

@testable import LibSignalClient
import SignalFfi
import XCTest

private func fakeAsyncRuntime() -> SignalConstPointerNonSuspendingBackgroundThreadRuntime {
    SignalConstPointerNonSuspendingBackgroundThreadRuntime(raw: OpaquePointer(bitPattern: -1))
}

private func invokeFnIgnoringResult<T>(fn: (UnsafeMutablePointer<T>?) -> SignalFfiErrorRef?) throws {
    // Swift doesn't have a way to declare uninitialized local variables, so we have to allocate one on the heap.
    // This will almost certainly get stack-promoted, but since this is a test it doesn't really matter anyway.
    let output = UnsafeMutablePointer<T>.allocate(capacity: 1)
    defer { output.deallocate() }
    try checkError(fn(output))
}

public class TestingIntBox: NativeHandleOwner<SignalMutPointerTestingIntBox> {
    override public class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerTestingIntBox>
    ) -> SignalFfiErrorRef? {
        return signal_testing_int_box_destroy(handle.pointer)
    }
}
extension SignalMutPointerTestingIntBox: SignalMutPointer {
    public func const() -> SignalConstPointerTestingIntBox {
        Self.ConstPointer(raw: self.raw)
    }

    public typealias ConstPointer = SignalConstPointerTestingIntBox

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
extension SignalConstPointerTestingIntBox: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

extension SignalMutPointerTestStream: SignalMutPointer {
    public func const() -> SignalConstPointerTestStream {
        .init(raw: self.raw)
    }

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
extension SignalConstPointerTestStream: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

extension SignalCPromiseTestStreamChunkFfiResult: PromiseStruct {
    public typealias Result = SignalTestStreamChunkFfiResult
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
            _ = try await invokeAsyncFunction {
                signal_testing_error_on_borrow_io($0, fakeAsyncRuntime(), nil)
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
            _ = try await invokeAsyncFunction {
                signal_testing_panic_on_borrow_io($0, fakeAsyncRuntime(), nil)
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
            _ = try await invokeAsyncFunction {
                signal_testing_panic_on_load_io($0, fakeAsyncRuntime(), nil, nil)
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
            _ = try await invokeAsyncFunction {
                signal_testing_panic_in_body_io($0, fakeAsyncRuntime(), nil)
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
            _ = try await invokeAsyncFunction {
                signal_testing_error_on_return_io($0, fakeAsyncRuntime(), nil)
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
            _ = try await invokeAsyncFunction {
                signal_testing_panic_on_return_io($0, fakeAsyncRuntime(), nil)
            }
            XCTFail("should have failed")
        } catch SignalError.internalError(_) {
            // good
        }
    }

    func testReturnStringArray() throws {
        let EXPECTED = ["easy", "as", "ABC", "123"]
        let array = try invokeFnReturningStringArray {
            signal_testing_return_string_array($0)
        }
        XCTAssertEqual(array, EXPECTED)
    }

    func testBytestringArray() throws {
        let first: [UInt8] = [1, 2, 3]
        let empty: [UInt8] = []
        let second: [UInt8] = [4, 5, 6]
        let result = try first.withUnsafeBytes { first in
            try empty.withUnsafeBytes { empty in
                try second.withUnsafeBytes { second in
                    let slices = [
                        SignalBorrowedBuffer(first), SignalBorrowedBuffer(empty), SignalBorrowedBuffer(second),
                    ]
                    return try slices.withUnsafeBufferPointer { slices in
                        try invokeFnReturningBytestringArray {
                            signal_testing_process_bytestring_array(
                                $0,
                                SignalBorrowedSliceOfBuffers(base: slices.baseAddress, length: slices.count)
                            )
                        }
                    }
                }
            }
        }
        XCTAssertEqual(result, [[1, 2, 3, 1, 2, 3], [], [4, 5, 6, 4, 5, 6]].map { Data($0) })
    }

    func testBytestringArrayEmpty() throws {
        let slices: [SignalBorrowedBuffer] = []
        let result = try slices.withUnsafeBufferPointer { slices in
            try invokeFnReturningBytestringArray {
                signal_testing_process_bytestring_array(
                    $0,
                    SignalBorrowedSliceOfBuffers(base: slices.baseAddress, length: slices.count)
                )
            }
        }
        XCTAssertEqual(result, [])
    }

    func testBridgedStringMap() throws {
        let empty = try [:].withBridgedStringMap { map in
            try invokeFnReturningString {
                signal_testing_bridged_string_map_dump_to_json($0, map.const())
            }
        }
        XCTAssertEqual(empty, "{}")

        let dumped = try ["b": "bbb", "a": "aaa", "c": "ccc"].withBridgedStringMap { map in
            try invokeFnReturningString {
                signal_testing_bridged_string_map_dump_to_json($0, map.const())
            }
        }
        XCTAssertEqual(
            dumped,
            """
            {
              "a": "aaa",
              "b": "bbb",
              "c": "ccc"
            }
            """
        )
    }

    func testReturnOptionalUuid() throws {
        let shouldBeNil = try invokeFnReturningOptionalUuid {
            signal_testing_convert_optional_uuid($0, false)
        }
        XCTAssertEqual(nil, shouldBeNil)
        let shouldBePresent = try invokeFnReturningOptionalUuid {
            signal_testing_convert_optional_uuid($0, true)
        }
        XCTAssertEqual(UUID(uuidString: "abababab-1212-8989-baba-565656565656"), shouldBePresent)
    }

    func testFingerprintVersionMismatchError() throws {
        let theirs = UInt32(11)
        let ours = UInt32(22)
        do {
            try checkError(signal_testing_fingerprint_version_mismatch_error(theirs, ours))
            XCTFail("should have thrown")
        } catch SignalError.fingerprintVersionMismatch(let actualTheirs, let actualOurs) {
            XCTAssertEqual(theirs, actualTheirs)
            XCTAssertEqual(ours, actualOurs)
        }
    }

    func testReturnPair() throws {
        let pair = try invokeFnReturningValueByPointer(.init()) {
            signal_testing_return_pair($0)
        }
        defer { signal_free_string(pair.second) }
        XCTAssertEqual(pair.first, 1 as Int32)
        XCTAssertEqual(String(cString: pair.second), "libsignal")
    }

    func testBridgeHandleRef() throws {
        let ptr = try invokeFnReturningValueByPointer(.init()) {
            signal_testing_testing_int_box_new($0, 17)
        }
        defer { signal_testing_int_box_destroy(ptr) }
        XCTAssertEqual(
            17,
            try invokeFnReturningInteger {
                signal_testing_testing_int_box_get($0, SignalConstPointerTestingIntBox(raw: ptr.raw))
            }
        )
    }
    func testBridgeHandleRefNice() throws {
        let ptr = try invokeFnReturningValueByPointer(.init()) {
            signal_testing_testing_int_box_new($0, 17)
        }
        let intBox = TestingIntBox(owned: NonNull(ptr)!)
        XCTAssertEqual(
            17,
            try NativeTestingNice.TESTING_TestingIntBox_Get(myIntBox: intBox)
        )
    }

    private class TestStream: NativeHandleOwner<SignalMutPointerTestStream> {
        override class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerTestStream>) -> SignalFfiErrorRef? {
            signal_test_stream_destroy(handle.pointer)
        }
    }

    private func wrapTestStream(_ stream: TestStream, cancelled: XCTestExpectation? = nil) -> ColdAsyncStream<String> {
        // It's not very efficient to give each stream its own tokio runtime,
        // but that's fine for testing.
        let asyncContext = TokioAsyncContext()
        return ColdAsyncStream(
            asyncContext: asyncContext,
            stream: stream,
            pull: { asyncContext, stream in
                try await asyncContext.invokeAsyncFunction { promise, asyncContext in
                    stream.withBorrowed { stream in
                        signal_testing_bulk_pull_from_stream_next_chunk(promise, asyncContext.const(), stream.const())
                    }
                }
            },
            convert: { result in
                let value = try DerivedReturnConverterTestStreamChunk.convertReturn(consuming: result)
                return (value.chunk, value.termination)
            },
            cancel: {
                cancelled?.fulfill()
                return signal_testing_bulk_pull_from_stream_cancel($0)
            }
        )
    }

    func testStreaming() async {
        let contents = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
        let rawStream: TestStream = contents.withUnsafeBorrowedBytestringArray { contents in
            try! invokeFnReturningNativeHandle {
                signal_testing_bulk_pull_from_stream_new($0, contents, false)
            }
        }
        let stream = wrapTestStream(rawStream)
        let received = try! await stream.reduce(into: []) { $0.append($1) }
        XCTAssertEqual(received, contents)
    }

    func testStreamingWithError() async {
        let contents = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
        let rawStream: TestStream = contents.withUnsafeBorrowedBytestringArray { contents in
            try! invokeFnReturningNativeHandle {
                signal_testing_bulk_pull_from_stream_new($0, contents, true)
            }
        }
        let stream = wrapTestStream(rawStream)
        let (received, maybeError) = await stream.collectUntilError()
        XCTAssertEqual(received, contents)
        switch maybeError {
        case nil:
            XCTFail("should have thrown")
        case SignalError.invalidArgument(let expected)?:
            XCTAssertEqual(expected, "error")
        case let error?:
            XCTFail("unexpected error: \(error)")
        }
    }

    func testStreamingWithCancellation() async {
        let contents = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
        let rawStream: TestStream = contents.withUnsafeBorrowedBytestringArray { contents in
            try! invokeFnReturningNativeHandle {
                signal_testing_bulk_pull_from_stream_new($0, contents, true)
            }
        }
        let expectCancel = XCTestExpectation(description: "stream cancelled")
        expectCancel.expectedFulfillmentCount = 3  // see below for why 3 and not the default 1
        let stream = wrapTestStream(rawStream, cancelled: expectCancel)

        var received = [String]()
        do {
            for try await next in stream {
                received.append(next)
                if received.count >= 3 {
                    stream.cancel()
                }
            }
            XCTFail("should have thrown")
        } catch SignalError.invalidArgument(let expected) {
            // This is thrown as an .invalidArgument because of the Rust-side type.
            XCTAssertEqual(expected, "cancelled")
            // Even though we cancelled at 3 items (and then again at 4 and 5 items!)
            // the entire first chunk is received. This is expected due to buffering.
            XCTAssertEqual(received, ["a", "b", "c", "d", "e"])
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        await fulfillment(of: [expectCancel], timeout: 0)
    }

    func testMapFailedBitPattern() {
        // Make sure our copy of MAP_FAILED is correct.
        XCTAssertEqual(BulkPolledStreamTerminationConverter.MAP_FAILED_BIT_PATTERN, Int(bitPattern: MAP_FAILED))
    }
}

#endif
