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
internal protocol Completable {
    associatedtype PromiseCallback
}

extension Bool: Completable {
    typealias PromiseCallback = SignalCPromisebool
}

extension Int32: Completable {
    typealias PromiseCallback = SignalCPromisei32
}

extension UnsafeRawPointer: Completable {
    typealias PromiseCallback = SignalCPromiseRawPointer
}
extension OpaquePointer: Completable {
    // C function pointer that takes two output arguments and one input argument.
    typealias PromiseCallback = (@convention(c) (
        _ error: SignalFfiErrorRef?,
        _ value: UnsafePointer<OpaquePointer?>?,
        _ context: UnsafeRawPointer?) -> Void)?
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
private class Completer<Value: Completable>: CompleterBase {
    init(continuation: CheckedContinuation<Value, Error>) {
        super.init { error, valuePtr in
            continuation.resume(with: Result {
                try checkError(error)
                guard let valuePtr else {
                    throw SignalError.internalError("produced neither an error nor a value")
                }
                // This is the part that preserves the type:
                // we assume that whatever pointer we've been handed does in fact point to a Value.
                return valuePtr.load(as: Value.self)
            })
        }
    }

    /// Generates the correct C callback for a promise that produces `Value` as a result.
    var callback: Value.PromiseCallback {
        typealias RawPromiseCallback = @convention(c) (_ error: SignalFfiErrorRef?, _ value: UnsafeRawPointer?, _ context: UnsafeRawPointer?) -> Void
        let completeOpaque: RawPromiseCallback = { error, value, context in
            let completer: CompleterBase = Unmanaged.fromOpaque(context!).takeRetainedValue()
            completer.completeUnsafe(error, value)
        }
        // We know UnsafeRawPointer and UnsafePointer<X> have the same representation,
        // so we can treat `completeOpaque` as a promise callback for any type.
        // We know it's the *correct* type (for this completer specifically!)
        // because of how `self.completeUnsafe` is initialized.
        return unsafeBitCast(completeOpaque, to: Value.PromiseCallback.self)
    }
}

/// Provides a callback and context for calling Promise-based libsignal\_ffi functions.
///
/// Example:
///
/// ```
/// let result: Int32 = try await invokeAsyncFunction {
///   signal_do_async_work($0, $1, someInput, someOtherInput)
/// }
/// ```
///
/// - Parameter resultType: Allows you to explicitly specify the result type if it cannot be inferred
/// - Parameter body: Call the libsignal\_ffi function here
internal func invokeAsyncFunction<Result: Completable>(
    returning resultType: Result.Type = Result.self,
    _ body: (Result.PromiseCallback, UnsafeRawPointer) -> SignalFfiErrorRef?
) async throws -> Result {
    try await withCheckedThrowingContinuation { continuation in
        let completer = Completer(continuation: continuation)
        let manuallyRetainedCompleter = Unmanaged.passRetained(completer)
        let startResult = body(completer.callback, manuallyRetainedCompleter.toOpaque())
        if let error = startResult {
            // Our completion callback is never going to get called, so we need to balance the `passRetained` above.
            _ = manuallyRetainedCompleter.takeRetainedValue()
            completer.completeUnsafe(error, nil)
        }
    }
}
