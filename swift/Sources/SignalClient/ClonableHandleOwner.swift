//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

public class ClonableHandleOwner {
    private enum MaybeOwnedHandle {
        case borrowed(OpaquePointer)
        case owned(OpaquePointer)
    }

    private var handle: MaybeOwnedHandle?

    internal var nativeHandle: OpaquePointer? {
        switch handle {
        case nil:
            return nil
        case .borrowed(let handle)?:
            return handle
        case .owned(let handle)?:
            return handle
        }
    }

    internal init(owned handle: OpaquePointer) {
        self.handle = .owned(handle)
    }

    internal init(borrowing handle: OpaquePointer?) {
        self.handle = handle.map { .borrowed($0) }
    }

    internal func replaceWithClone() {
        guard case .borrowed(let currentHandle)? = self.handle else {
            preconditionFailure("replaceWithClone() called for a handle that's already owned")
        }
        var newHandle: OpaquePointer?
        // Automatic cloning must not fail.
        failOnError(Self.cloneNativeHandle(&newHandle, currentHandle: currentHandle))
        self.handle = .owned(newHandle!)
    }

    fileprivate func takeNativeHandle() -> OpaquePointer? {
        if case .borrowed? = self.handle {
            preconditionFailure("borrowed handle may have escaped")
        }
        defer { handle = nil }
        return nativeHandle
    }

    fileprivate func forgetBorrowedHandle() {
        guard case .borrowed? = self.handle else {
            preconditionFailure("forgetBorrowedHandle() called for an owned handle")
        }
        handle = nil
    }

    internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        fatalError("\(self) does not support cloning")
    }

    internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        fatalError("must be implemented by subclasses")
    }

    deinit {
        switch handle {
        case nil:
            return
        case .borrowed?:
            preconditionFailure("borrowed handle may have escaped")
        case .owned(let handle)?:
            failOnError(Self.destroyNativeHandle(handle))
        }
    }
}

/// Ensures that `handleOwner` actually does own its handle by cloning it.
///
/// As an optimization, steals the handle if `handleOwner` has no other references.
/// Checking this requires using `inout`; the reference itself won't be modified.
internal func cloneOrForgetAsNeeded<Owner: ClonableHandleOwner>(_ handleOwner: inout Owner) {
    if isKnownUniquelyReferenced(&handleOwner) {
        handleOwner.forgetBorrowedHandle()
    } else {
        handleOwner.replaceWithClone()
    }
}

/// Clones the handle owned by `handleOwner`.
///
/// As an optimization, steals the handle if `handleOwner` has no other references.
/// Checking this requires using `inout`; the reference itself won't be modified.
internal func cloneOrTakeHandle<Owner: ClonableHandleOwner>(from handleOwner: inout Owner) throws -> OpaquePointer? {
    if isKnownUniquelyReferenced(&handleOwner) {
        return handleOwner.takeNativeHandle()
    }

    var result: OpaquePointer?
    try checkError(type(of: handleOwner).cloneNativeHandle(&result, currentHandle: handleOwner.nativeHandle))
    return result
}
