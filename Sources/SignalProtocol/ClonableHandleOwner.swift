class ClonableHandleOwner {
    enum MaybeOwnedHandle {
        case none
        case unowned(OpaquePointer)
        case owned(OpaquePointer)
    }

    private var handle: MaybeOwnedHandle

    internal var nativeHandle: OpaquePointer? {
        switch handle {
        case .none:
            return nil
        case .unowned(let handle):
            return handle
        case .owned(let handle):
            return handle
        }
    }

    internal init(owned handle: OpaquePointer) {
        self.handle = .owned(handle)
    }

    internal init(unowned handle: OpaquePointer?) {
        self.handle = handle.map { .unowned($0) } ?? .none
    }

    internal func replaceWithClone() {
        guard case .unowned(let currentHandle) = self.handle else {
            preconditionFailure("replaceWithClone() called for a handle that's already owned")
        }
        var newHandle: OpaquePointer?
        // Automatic cloning must not fail.
        try! CheckError(Self.cloneNativeHandle(&newHandle, currentHandle: currentHandle))
        self.handle = .owned(newHandle!)
    }

    fileprivate func takeNativeHandle() -> OpaquePointer? {
        if case .unowned = self.handle {
            preconditionFailure("unowned handle may have escaped")
        }
        defer { handle = .none }
        return nativeHandle
    }

    fileprivate func forgetUnownedHandle() {
        guard case .unowned = self.handle else {
            preconditionFailure("forgetUnownedHandle() called for an owned handle")
        }
        handle = .none
    }

    internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        fatalError("\(self) does not support cloning")
    }

    internal class func destroyNativeHandle(_ handle: OpaquePointer) {
        fatalError("must be implemented by subclasses")
    }

    deinit {
        switch handle {
        case .none:
            return
        case .unowned(_):
            preconditionFailure("unowned handle may have escaped")
        case .owned(let handle):
            Self.destroyNativeHandle(handle)
        }
    }
}

/// Ensures that `handleOwner` actually does own its handle by cloning it.
///
/// As an optimization, steals the handle if `handleOwner` has no other references.
/// Checking this requires using `inout`; the reference itself won't be modified.
func cloneOrForgetAsNeeded<Owner: ClonableHandleOwner>(_ handleOwner: inout Owner) {
    if isKnownUniquelyReferenced(&handleOwner) {
        handleOwner.forgetUnownedHandle()
    } else {
        handleOwner.replaceWithClone()
    }
}

/// Clones the handle owned by `handleOwner`.
///
/// As an optimization, steals the handle if `handleOwner` has no other references.
/// Checking this requires using `inout`; the reference itself won't be modified.
func cloneOrTakeHandle<Owner: ClonableHandleOwner>(from handleOwner: inout Owner) throws -> OpaquePointer? {
    if isKnownUniquelyReferenced(&handleOwner) {
        return handleOwner.takeNativeHandle()
    }

    var result: OpaquePointer?
    try CheckError(type(of: handleOwner).cloneNativeHandle(&result, currentHandle: handleOwner.nativeHandle))
    return result
}
