/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.libsignal.internal

import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.CancellationException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Awaits for completion of this CompletableFuture without blocking a thread.
 *
 * This suspending function is cancellable. If the coroutine is cancelled while
 * this function is suspended, the future will be cancelled as well.
 *
 * @return The result value of the CompletableFuture
 * @throws Exception if the CompletableFuture completed exceptionally
 * @throws CancellationException if the coroutine was cancelled
 */
public suspend fun <T> CompletableFuture<T>.await(): T =
  suspendCancellableCoroutine { c ->
    // From https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines/-cancellable-continuation/
    val future = this
    future.whenComplete { result, throwable ->
      if (throwable != null) {
        // Resume continuation with an exception if an external source failed
        c.resumeWithException(throwable)
      } else {
        // Resume continuation with a value if it was computed
        c.resume(result)
      }
    }
    // Cancel the computation if the continuation itself was cancelled because a caller of 'await' is cancelled
    c.invokeOnCancellation {
      future.cancel(true)
    }
  }

/**
 * Transforms a CompletableFuture<T> into a CompletableFuture<R> with proper bidirectional cancellation.
 *
 * This helper wraps a native future and transforms its result, while ensuring that:
 * - Success values are transformed using the provided mapper
 * - CancellationExceptions propagate as cancellations (not completions)
 * - Other exceptions are transformed using the error mapper
 * - Cancellation of the outer future cancels the inner future
 *
 * @param onSuccess Function to transform success values from T to R
 * @param onError Function to transform non-cancellation exceptions to R
 * @return A new CompletableFuture<R> with bidirectional cancellation support
 */
public fun <T, R> CompletableFuture<T>.mapWithCancellation(
  onSuccess: (T) -> R,
  onError: (Throwable) -> R,
): CompletableFuture<R> {
  val outer = CompletableFuture<R>()

  this.whenComplete { value, err ->
    when (err) {
      null -> outer.complete(onSuccess(value))
      is CancellationException -> outer.cancel(true)
      else -> outer.complete(onError(err))
    }
  }

  outer.whenComplete { _, t ->
    if (t is CancellationException) {
      this.cancel(true)
    }
  }

  return outer
}

/**
 * Converts a `CompletableFuture<T>` to a `CompletableFuture<Result<T>>`.
 *
 * This helper function wraps the result of a CompletableFuture in a Result,
 * catching any exceptions and converting them to `Result.failure()`.
 *
 * Uses libsignal's chaining mechanism to ensure proper bidirectional cancellation
 * propagation for long async operations, like network requests.
 *
 * @return A new CompletableFuture that completes with `Result.success(value)` or `Result.failure(exception)`
 */
public fun <T> CompletableFuture<T>.toResultFuture(): CompletableFuture<Result<T>> =
  this.handle { value, throwable ->
    if (throwable == null) {
      Result.success(value)
    } else {
      Result.failure(throwable)
    }
  }
