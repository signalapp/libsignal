/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.libsignal.internal

import kotlinx.coroutines.suspendCancellableCoroutine
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
suspend fun <T> CompletableFuture<T>.await(): T = suspendCancellableCoroutine { c ->
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
