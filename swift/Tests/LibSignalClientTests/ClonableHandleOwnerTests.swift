//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
@testable import LibSignalClient

private struct FakeHandle {
    // We're using the tuple to guarantee in-memory layout for this test.
    // It's a little sketchy but it keeps the test from getting more complicated.
    // swiftlint:disable:next large_tuple
    var destroyed: (original: Bool, clone: Bool, redzone: Bool) = (false, false, true)
}

private class MockClonableHandleOwner: ClonableHandleOwner {
    override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        XCTAssertFalse(UnsafePointer<Bool>(currentHandle!).pointee)
        newHandle = OpaquePointer(UnsafePointer<Bool>(currentHandle!) + 1)
        return nil
    }

    override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        UnsafeMutablePointer<Bool>(handle).pointee = true
        return nil
    }
}

class ClonableHandleOwnerTests: XCTestCase {
    func testOwned() {
        var handle = FakeHandle()
        withUnsafeMutablePointer(to: &handle) {
            _ = MockClonableHandleOwner(owned: OpaquePointer($0))
        }
        XCTAssertTrue(handle.destroyed.original)
        XCTAssertFalse(handle.destroyed.clone)
    }

    func testBorrowAndForget() {
        var handle = FakeHandle()
        withUnsafeMutablePointer(to: &handle) {
            var owner = MockClonableHandleOwner(borrowing: OpaquePointer($0))
            cloneOrForgetAsNeeded(&owner)
        }
        XCTAssertFalse(handle.destroyed.original)
        XCTAssertFalse(handle.destroyed.clone)
    }

    func testBorrowAndEscape() {
        var handle = FakeHandle()
        withUnsafeMutablePointer(to: &handle) {
            var owner = MockClonableHandleOwner(borrowing: OpaquePointer($0))
            let fakeEscape = Unmanaged.passRetained(owner)
            cloneOrForgetAsNeeded(&owner)
            fakeEscape.release()
        }
        XCTAssertFalse(handle.destroyed.original)
        XCTAssertTrue(handle.destroyed.clone)
    }

    func testTake() {
        var handle = FakeHandle()
        withUnsafeMutablePointer(to: &handle) {
            var owner = MockClonableHandleOwner(owned: OpaquePointer($0))
            let takenHandle = try! cloneOrTakeHandle(from: &owner)
            XCTAssertEqual(takenHandle, OpaquePointer($0))
        }
        XCTAssertFalse(handle.destroyed.original)
        XCTAssertFalse(handle.destroyed.clone)
    }

    func testTakeAfterEscape() {
        var handle = FakeHandle()
        withUnsafeMutablePointer(to: &handle) {
            var owner = MockClonableHandleOwner(owned: OpaquePointer($0))
            let fakeEscape = Unmanaged.passRetained(owner)
            let takenHandle = try! cloneOrTakeHandle(from: &owner)
            XCTAssertEqual(UnsafeRawPointer(takenHandle), UnsafeRawPointer($0) + 1)
            let takenHandle2 = try! cloneOrTakeHandle(from: &owner)
            XCTAssertEqual(UnsafeRawPointer(takenHandle2), UnsafeRawPointer($0) + 1)
            fakeEscape.release()
        }
        XCTAssertTrue(handle.destroyed.original)
        XCTAssertFalse(handle.destroyed.clone)
    }
}
