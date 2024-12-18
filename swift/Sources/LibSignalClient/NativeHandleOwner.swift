//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// Wrapper for an ``OpaquePointer?`` allocated by native code.
public protocol SignalMutPointer {
    associatedtype ConstPointer: SignalConstPointer

    init(untyped: OpaquePointer?)
    func toOpaque() -> OpaquePointer?
    func const() -> ConstPointer
}

/// Wrapper for an ``OpaquePointer?`` only used as a const argument.
public protocol SignalConstPointer {
    func toOpaque() -> OpaquePointer?
}

public struct NonNull<PointerType: SignalMutPointer> {
    private var opaquePointer: OpaquePointer

    internal init?(_ p: any SignalMutPointer) {
        guard let pointer = p.toOpaque() else {
            return nil
        }
        self.opaquePointer = pointer
    }

    fileprivate init(untyped: OpaquePointer) {
        self.opaquePointer = untyped
    }

    internal var opaque: OpaquePointer {
        return self.opaquePointer
    }

    internal var pointer: PointerType {
        return PointerType(untyped: self.opaquePointer)
    }
}

extension OpaquePointer?: SignalMutPointer, SignalConstPointer {
    public typealias ConstPointer = OpaquePointer?

    public init(untyped: OpaquePointer?) {
        self = untyped
    }

    public func toOpaque() -> OpaquePointer? {
        return self
    }

    public func const() -> OpaquePointer? {
        return self
    }
}

public class NativeHandleOwner<PointerType: SignalMutPointer> {
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

    internal required init(owned handle: NonNull<PointerType>) {
        self.handle = .owned(handle.opaque)
    }

    fileprivate init(borrowing handle: PointerType.ConstPointer) {
        self.handle = handle.toOpaque().map { .borrowed($0) }
    }

    internal class func destroyNativeHandle(_: NonNull<PointerType>) -> SignalFfiErrorRef? {
        fatalError("must be implemented by subclasses")
    }

    deinit {
        switch handle {
        case nil:
            return
        case .borrowed?:
            preconditionFailure("borrowed handle may have escaped")
        case .owned(let handle)?:
            failOnError(Self.destroyNativeHandle(NonNull(untyped: handle)))
        }
    }

    /// Provides access to the wrapped Rust object pointer while keeping the wrapper alive.
    ///
    /// See also the free functions `withNativeHandles(…)`,
    /// which make it convenient to access the native handles of multiple objects.
    internal func withNativeHandle<R>(_ callback: (PointerType) throws -> R) rethrows -> R {
        return try withExtendedLifetime(self) {
            try callback(PointerType(untyped: self.unsafeNativeHandle))
        }
    }
}

@available(*, unavailable, message: "use the method form instead")
internal func withNativeHandle<PointerType, Result>(_: NativeHandleOwner<PointerType>, _: (OpaquePointer?) throws -> Result) rethrows -> Result {
    fatalError()
}

internal func withNativeHandles<PointerA, PointerB, Result>(_ a: NativeHandleOwner<PointerA>, _ b: NativeHandleOwner<PointerB>, _ callback: (PointerA, PointerB) throws -> Result) rethrows -> Result {
    return try a.withNativeHandle { aHandle in
        try b.withNativeHandle { bHandle in
            try callback(aHandle, bHandle)
        }
    }
}

internal func withNativeHandles<PointerA, PointerB, PointerC, Result>(_ a: NativeHandleOwner<PointerA>, _ b: NativeHandleOwner<PointerB>, _ c: NativeHandleOwner<PointerC>, _ callback: (PointerA, PointerB, PointerC) throws -> Result) rethrows -> Result {
    return try a.withNativeHandle { aHandle in
        try b.withNativeHandle { bHandle in
            try c.withNativeHandle { cHandle in
                try callback(aHandle, bHandle, cHandle)
            }
        }
    }
}

internal func withNativeHandles<PointerA, PointerB, PointerC, PointerD, Result>(_ a: NativeHandleOwner<PointerA>, _ b: NativeHandleOwner<PointerB>, _ c: NativeHandleOwner<PointerC>, _ d: NativeHandleOwner<PointerD>, _ callback: (PointerA, PointerB, PointerC, PointerD) throws -> Result) rethrows -> Result {
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

public class ClonableHandleOwner<PointerType: SignalMutPointer>: NativeHandleOwner<PointerType> {
    internal required init(owned handle: NonNull<PointerType>) {
        super.init(owned: handle)
    }

    override internal init(borrowing handle: PointerType.ConstPointer) {
        super.init(borrowing: handle)
    }

    internal func replaceWithClone() {
        guard case .borrowed(let currentHandle)? = self.handle else {
            preconditionFailure("replaceWithClone() called for a handle that's already owned")
        }
        var newHandle = PointerType(untyped: nil)
        // Automatic cloning must not fail.
        failOnError(Self.cloneNativeHandle(&newHandle, currentHandle: PointerType(untyped: currentHandle).const()))
        self.handle = .owned(newHandle.toOpaque()!)
    }

    fileprivate func takeNativeHandle() -> PointerType {
        defer { handle = nil }

        switch handle {
        case nil:
            return PointerType(untyped: nil)
        case .borrowed(_):
            preconditionFailure("borrowed handle may have escaped")
        case .owned(let ptr):
            return PointerType(untyped: ptr)
        }
    }

    fileprivate func forgetBorrowedHandle() {
        guard case .borrowed? = self.handle else {
            preconditionFailure("forgetBorrowedHandle() called for an owned handle")
        }
        handle = nil
    }

    internal class func cloneNativeHandle(_ newHandle: inout PointerType, currentHandle: PointerType.ConstPointer) -> SignalFfiErrorRef? {
        fatalError("must be implemented by subclasses")
    }
}

/// Ensures that `handleOwner` actually does own its handle by cloning it.
///
/// As an optimization, steals the handle if `handleOwner` has no other references.
/// Checking this requires using `inout`; the reference itself won't be modified.
internal func cloneOrForgetAsNeeded<Owner: ClonableHandleOwner<PointerType>, PointerType>(_ handleOwner: inout Owner) {
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
internal func cloneOrTakeHandle<Owner: ClonableHandleOwner<PointerType>, PointerType>(from handleOwner: inout Owner) throws -> PointerType {
    if isKnownUniquelyReferenced(&handleOwner) {
        return handleOwner.takeNativeHandle()
    }

    var result = PointerType(untyped: nil)
    try handleOwner.withNativeHandle {
        try checkError(type(of: handleOwner).cloneNativeHandle(&result, currentHandle: $0.const()))
    }
    return result
}
