//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** A stripped-down, Android-21-compatible version of java.util.concurrent.CompletableFuture. */
public class CompletableFuture<T> implements Future<T> {
  private boolean completed;
  private T result;
  private Throwable exception;

  public CompletableFuture() {}

  @Override
  public synchronized boolean cancel(boolean mayInterruptIfRunning) {
    // We do not currently support cancellation.
    return false;
  }

  @Override
  public synchronized boolean isCancelled() {
    return false;
  }

  @Override
  public synchronized boolean isDone() {
    return completed;
  }

  public synchronized boolean complete(T result) {
    if (completed) return false;

    this.result = result;
    this.completed = true;

    notifyAll();
    return true;
  }

  public synchronized boolean completeExceptionally(Throwable throwable) {
    if (completed) return false;

    if (throwable == null) {
      throwable = new AssertionError("Future failed, but no exception provided");
    }

    this.exception = throwable;
    this.completed = true;

    notifyAll();
    return true;
  }

  @Override
  public synchronized T get()
      throws CancellationException, ExecutionException, InterruptedException {
    while (!completed) wait();

    if (exception != null) throw new ExecutionException(exception);

    return result;
  }

  @Override
  public synchronized T get(long timeout, TimeUnit unit)
      throws CancellationException, ExecutionException, InterruptedException, TimeoutException {
    long deadlineMillis = System.currentTimeMillis() + unit.toMillis(timeout);

    while (!completed) {
      long remainingMillis = deadlineMillis - System.currentTimeMillis();
      if (remainingMillis <= 0) {
        throw new TimeoutException();
      }

      wait(remainingMillis);
    }

    return get();
  }
}
