//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// Wrapper for an `OpaquePointer?` allocated by native code.
public protocol SignalMutPointer {
    associatedtype ConstPointer: SignalConstPointer

    init(untyped: OpaquePointer?)
    func toOpaque() -> OpaquePointer?
    func const() -> ConstPointer
}

/// Wrapper for an `OpaquePointer?` only used as a const argument.
public protocol SignalConstPointer {
    func toOpaque() -> OpaquePointer?
}

public struct NonNull<PointerType: SignalMutPointer> {
    private var opaquePointer: OpaquePointer

    internal init?(_ p: PointerType) {
        guard let pointer = p.toOpaque() else {
            return nil
        }
        self.opaquePointer = pointer
    }

    internal init(untyped: OpaquePointer) {
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
    /// Returns the native handle (if any) without any lifetime guarantees.
    ///
    /// You should probably use `withNativeHandle(_:)`
    /// unless you can't use block scoping to keep the owner (`self`) alive.
    internal fileprivate(set) var unsafeNativeHandle: PointerType

    internal required init(owned handle: NonNull<PointerType>) {
        self.unsafeNativeHandle = handle.pointer
    }

    internal class func destroyNativeHandle(_ handle: NonNull<PointerType>) -> SignalFfiErrorRef? {
        fatalError("must be implemented by subclasses")
    }

    deinit {
        if let handle = NonNull(unsafeNativeHandle) {
            failOnError(Self.destroyNativeHandle(handle))
        }
    }

    /// Provides access to the wrapped Rust object pointer while keeping the wrapper alive.
    ///
    /// See also the free function ``withAllBorrowed(_:in:)``,
    /// which makes it convenient to access the native handles of multiple objects.
    internal func withNativeHandle<R>(_ callback: (PointerType) throws -> R) rethrows -> R {
        return try withExtendedLifetime(self) {
            try callback(self.unsafeNativeHandle)
        }
    }
}

public class ClonableHandleOwner<PointerType: SignalMutPointer>: NativeHandleOwner<PointerType> {
    internal required init(owned handle: NonNull<PointerType>) {
        super.init(owned: handle)
    }

    fileprivate func takeNativeHandle() -> PointerType {
        defer { unsafeNativeHandle = PointerType(untyped: nil) }
        return unsafeNativeHandle
    }

    internal class func cloneNativeHandle(
        _ handle: inout PointerType,
        currentHandle: PointerType.ConstPointer
    ) -> SignalFfiErrorRef? {
        fatalError("must be implemented by subclasses")
    }
}

/// Clones the handle owned by `handleOwner`.
///
/// As an optimization, steals the handle if `handleOwner` has no other references.
/// Checking this requires using `inout`; the reference itself won't be modified.
internal func cloneOrTakeHandle<Owner: ClonableHandleOwner<PointerType>, PointerType>(
    from handleOwner: inout Owner
) throws -> PointerType {
    if isKnownUniquelyReferenced(&handleOwner) {
        return handleOwner.takeNativeHandle()
    }

    var result = PointerType(untyped: nil)
    try handleOwner.withNativeHandle {
        try checkError(type(of: handleOwner).cloneNativeHandle(&result, currentHandle: $0.const()))
    }
    return result
}
