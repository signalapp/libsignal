//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

public class NativeHandleOwner {
    fileprivate enum MaybeOwnedHandle {
        case borrowed(OpaquePointer)
        case owned(OpaquePointer)
    }

    fileprivate var handle: MaybeOwnedHandle?

    /// Returns the native handle (if any) without any lifetime guarantees.
    ///
    /// You should probably use `withNativeHandle(_:)`
    /// unless you can't use block scoping to keep the owner (`self`) alive.
    internal var unsafeNativeHandle: OpaquePointer? {
        switch self.handle {
        case nil:
            return nil
        case .borrowed(let handle)?:
            return handle
        case .owned(let handle)?:
            return handle
        }
    }

    internal required init(owned handle: OpaquePointer) {
        self.handle = .owned(handle)
    }

    fileprivate init(borrowing handle: OpaquePointer?) {
        self.handle = handle.map { .borrowed($0) }
    }

    internal class func destroyNativeHandle(_: OpaquePointer) -> SignalFfiErrorRef? {
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

    /// Provides access to the wrapped Rust object pointer while keeping the wrapper alive.
    ///
    /// See also the free functions `withNativeHandles(…)`,
    /// which make it convenient to access the native handles of multiple objects.
    internal func withNativeHandle<R>(_ callback: (OpaquePointer?) throws -> R) rethrows -> R {
        return try withExtendedLifetime(self) {
            try callback(self.unsafeNativeHandle)
        }
    }
}

@available(*, unavailable, message: "use the method form instead")
internal func withNativeHandle<Result>(_: NativeHandleOwner, _: (OpaquePointer?) throws -> Result) rethrows -> Result {
    fatalError()
}

internal func withNativeHandles<Result>(_ a: NativeHandleOwner, _ b: NativeHandleOwner, _ callback: (OpaquePointer?, OpaquePointer?) throws -> Result) rethrows -> Result {
    return try a.withNativeHandle { aHandle in
        try b.withNativeHandle { bHandle in
            try callback(aHandle, bHandle)
        }
    }
}

internal func withNativeHandles<Result>(_ a: NativeHandleOwner, _ b: NativeHandleOwner, _ c: NativeHandleOwner, _ callback: (OpaquePointer?, OpaquePointer?, OpaquePointer?) throws -> Result) rethrows -> Result {
    return try a.withNativeHandle { aHandle in
        try b.withNativeHandle { bHandle in
            try c.withNativeHandle { cHandle in
                try callback(aHandle, bHandle, cHandle)
            }
        }
    }
}

internal func withNativeHandles<Result>(_ a: NativeHandleOwner, _ b: NativeHandleOwner, _ c: NativeHandleOwner, _ d: NativeHandleOwner, _ callback: (OpaquePointer?, OpaquePointer?, OpaquePointer?, OpaquePointer?) throws -> Result) rethrows -> Result {
    return try a.withNativeHandle { aHandle in
        try b.withNativeHandle { bHandle in
            try c.withNativeHandle { cHandle in
                try d.withNativeHandle { dHandle in
                    try callback(aHandle, bHandle, cHandle, dHandle)
                }
            }
        }
    }
}

public class ClonableHandleOwner: NativeHandleOwner {
    internal required init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    override internal init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
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
        defer { handle = nil }

        switch handle {
        case nil:
            return nil
        case .borrowed(_):
            preconditionFailure("borrowed handle may have escaped")
        case .owned(let ptr):
            return ptr
        }
    }

    fileprivate func forgetBorrowedHandle() {
        guard case .borrowed? = self.handle else {
            preconditionFailure("forgetBorrowedHandle() called for an owned handle")
        }
        handle = nil
    }

    internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        fatalError("must be implemented by subclasses")
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
    try handleOwner.withNativeHandle {
        try checkError(type(of: handleOwner).cloneNativeHandle(&result, currentHandle: $0))
    }
    return result
}
