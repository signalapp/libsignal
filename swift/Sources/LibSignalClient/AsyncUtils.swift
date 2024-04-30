//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi

/// Used to check types for values produced asynchronously by Rust.
///
/// Swift doesn't allow generics to be used with `@convention(c)` functions, even in pointer position,
/// so we can't go from, say, `Int32` to `SignalCPromisei32` (a function taking `UnsafePointer<Int32>`,
/// among other arguments). This protocol explicitly associates a result type with a callback, so that
/// calls to `invokeAsyncFunction` can tell you if you got the result type wrong.
///
/// Note that implementing this is **unchecked;** make sure you match up the types correctly!
internal protocol PromiseStruct {
    associatedtype Result
}

extension SignalCPromisebool: PromiseStruct {
    typealias Result = Bool
}

extension SignalCPromisei32: PromiseStruct {
    typealias Result = Int32
}

extension SignalCPromiseRawPointer: PromiseStruct {
    typealias Result = UnsafeRawPointer
}

extension SignalCPromiseCdsiLookup: PromiseStruct {
    typealias Result = OpaquePointer
}

extension SignalCPromiseFfiCdsiLookupResponse: PromiseStruct {
    typealias Result = SignalFfiCdsiLookupResponse
}

extension SignalCPromiseFfiChatResponse: PromiseStruct {
    typealias Result = SignalFfiChatResponse
}

extension SignalCPromiseFfiChatServiceDebugInfo: PromiseStruct {
    typealias Result = SignalFfiChatServiceDebugInfo
}

extension SignalCPromiseFfiResponseAndDebugInfo: PromiseStruct {
    typealias Result = SignalFfiResponseAndDebugInfo
}

extension SignalCPromiseOwnedBufferOfc_uchar: PromiseStruct {
    typealias Result = SignalOwnedBuffer
}

/// A type-erased version of ``Completer``.
///
/// Not for direct use, see Completer instead.
private class CompleterBase {
    let completeUnsafe: (_ error: SignalFfiErrorRef?, _ valuePtr: UnsafeRawPointer?) -> Void

    init(completeUnsafe: @escaping (SignalFfiErrorRef?, UnsafeRawPointer?) -> Void) {
        self.completeUnsafe = completeUnsafe
    }
}

/// Part of the implementation of ``invokeAsyncFunction``.
///
/// A Completer wraps a [CheckedContinuation][] in a way that erases the type,
/// so that it can be completed from a libsignal\_ffi Promise without needing
/// a separate implementation for each result type. This is a limitation that
/// comes from Swift's run-time generics model not being compatible with
/// `@convention(c)` functions.
///
/// It is a class so that it can be passed in a C-style context pointer.
///
/// [CheckedContinuation]: https://developer.apple.com/documentation/swift/checkedcontinuation
private class Completer<Promise: PromiseStruct>: CompleterBase {
    init(continuation: CheckedContinuation<Promise.Result, Error>) {
        super.init { error, valuePtr in
            continuation.resume(with: Result {
                try checkError(error)
                guard let valuePtr else {
                    throw SignalError.internalError("produced neither an error nor a value")
                }
                // This is the part that preserves the type:
                // we assume that whatever pointer we've been handed does in fact point to a Promise.Result.
                return valuePtr.load(as: Promise.Result.self)
            })
        }
    }

    /// Generates the correct C callback for a promise that produces `Value` as a result.
    ///
    /// This retains `self`, to be used as the C context pointer for the callback.
    /// You must ensure that either the callback is called, or the result is passed to
    /// ``destroyUncompletedPromiseStruct(_:)``.
    func makePromiseStruct() -> Promise {
        typealias RawPromiseCallback = @convention(c) (_ error: SignalFfiErrorRef?, _ value: UnsafeRawPointer?, _ context: UnsafeRawPointer?) -> Void
        let completeOpaque: RawPromiseCallback = { error, value, context in
            let completer: CompleterBase = Unmanaged.fromOpaque(context!).takeRetainedValue()
            completer.completeUnsafe(error, value)
        }

        // We know UnsafeRawPointer and UnsafePointer<X> have the same representation,
        // so we can treat `completeOpaque` as a promise callback for any type.
        // We know it's the *correct* type (for this completer specifically!)
        // because of how `self.completeUnsafe` is initialized.
        // So first we build a promise struct---it doesn't matter which one---by reinterpreting the callback...
        typealias RawPointerPromiseCallback = @convention(c) (_ error: SignalFfiErrorRef?, _ value: UnsafePointer<UnsafeRawPointer?>?, _ context: UnsafeRawPointer?) -> Void
        let rawPromiseStruct = SignalCPromiseRawPointer(complete: unsafeBitCast(completeOpaque, to: RawPointerPromiseCallback.self), context: Unmanaged.passRetained(self).toOpaque())

        // ...And then we reinterpret the entire struct, because all promise structs *also* have the same layout.
        // (Which we at least check a little bit here.)
        // This is like doing a memcpy in C between two structs with compatible layouts.
        // This all definitely isn't ideal---we're sidestepping all of Swift's type safety!---
        // but it gives us type safety *elsewhere*.
        precondition(MemoryLayout<SignalCPromiseRawPointer>.size == MemoryLayout<Promise>.size)
        return unsafeBitCast(rawPromiseStruct, to: Promise.self)
    }

    func destroyUncompletedPromiseStruct(_ promiseStruct: Promise) {
        // Double-check that all promise structs have the same layout, then reverse what we did above.
        precondition(MemoryLayout<SignalCPromiseRawPointer>.size == MemoryLayout<Promise>.size)
        let rawPromiseStruct = unsafeBitCast(promiseStruct, to: SignalCPromiseRawPointer.self)
        Unmanaged<CompleterBase>.fromOpaque(rawPromiseStruct.context!).release()
    }
}

/// Provides a context struct for calling Promise-based libsignal\_ffi functions.
///
/// Example:
///
/// ```
/// let result: Int32 = try await invokeAsyncFunction {
///   signal_do_async_work($0, someInput, someOtherInput)
/// }
/// ```
internal func invokeAsyncFunction<Promise: PromiseStruct>(
    _ body: (UnsafeMutablePointer<Promise>) -> SignalFfiErrorRef?
) async throws -> Promise.Result {
    try await withCheckedThrowingContinuation { continuation in
        let completer = Completer<Promise>(continuation: continuation)
        var promiseStruct = completer.makePromiseStruct()
        let startResult = body(&promiseStruct)
        if let error = startResult {
            // Our completion callback is never going to get called, so we need to balance the `passRetained` above.
            completer.destroyUncompletedPromiseStruct(promiseStruct)
            completer.completeUnsafe(error, nil)
            return
        }
    }
}
