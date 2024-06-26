//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

internal class TokioAsyncContext: NativeHandleOwner {
    convenience init() {
        var handle: OpaquePointer?
        failOnError(signal_tokio_async_context_new(&handle))
        self.init(owned: handle!)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        signal_tokio_async_context_destroy(handle)
    }

    /// A thread-safe helper for translating Swift task cancellations into calls to
    /// `signal_tokio_async_context_cancel`.
    private class CancellationHandoffHelper {
        enum State {
            case initial
            case started(SignalCancellationId)
            case cancelled
        }

        // Emulates Rust's `Mutex<State>` (and the containing class is providing an `Arc`)
        // Unfortunately, doing this in Swift requires a separate allocation for the lock today.
        var state: State = .initial
        var lock = NSLock()

        let context: TokioAsyncContext

        init(context: TokioAsyncContext) {
            self.context = context
        }

        func setCancellationId(_ id: SignalCancellationId) {
            // Ideally we would use NSLock.withLock here, but that's not available on Linux,
            // which we still support for development and CI.
            do {
                self.lock.lock()
                defer { self.lock.unlock() }

                switch self.state {
                case .initial:
                    self.state = .started(id)
                    fallthrough
                case .started(_):
                    return
                case .cancelled:
                    break
                }
            }

            // If we didn't early-exit, we're already cancelled.
            self.cancel(id)
        }

        func cancel() {
            let cancelId: SignalCancellationId
            // Ideally we would use NSLock.withLock here, but that's not available on Linux,
            // which we still support for development and CI.
            do {
                self.lock.lock()
                defer { self.lock.unlock() }

                defer { state = .cancelled }
                switch self.state {
                case .started(let id):
                    cancelId = id
                case .initial, .cancelled:
                    return
                }
            }

            // If we didn't early-exit, the task has already started and we need to cancel it.
            self.cancel(cancelId)
        }

        func cancel(_ id: SignalCancellationId) {
            do {
                try self.context.withNativeHandle {
                    try checkError(signal_tokio_async_context_cancel($0, id))
                }
            } catch {
                NSLog("failed to cancel libsignal task %ld: %@", id, "\(error)")
            }
        }
    }

    /// Provides a callback and context for calling Promise-based libsignal\_ffi functions, with cancellation supported.
    ///
    /// Example:
    ///
    /// ```
    /// let result = try await asyncContext.invokeAsyncFunction { promise, runtime in
    ///   signal_do_async_work(promise, runtime, someInput, someOtherInput)
    /// }
    /// ```
    internal func invokeAsyncFunction<Promise: PromiseStruct>(
        _ body: (UnsafeMutablePointer<Promise>, OpaquePointer?) -> SignalFfiErrorRef?
    ) async throws -> Promise.Result {
        let cancellationHelper = CancellationHandoffHelper(context: self)
        return try await withTaskCancellationHandler(operation: {
            try await LibSignalClient.invokeAsyncFunction({ promise in
                withNativeHandle { handle in
                    body(promise, handle)
                }
            }, saveCancellationId: {
                cancellationHelper.setCancellationId($0)
            })
        }, onCancel: {
            cancellationHelper.cancel()
        })
    }
}
