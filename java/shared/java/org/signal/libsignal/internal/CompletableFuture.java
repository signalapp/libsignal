//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

/** A stripped-down, Android-21-compatible version of java.util.concurrent.CompletableFuture. */
public class CompletableFuture<T> implements Future<T> {
  private boolean completed;
  private T result;
  private Throwable exception;
  private List<ThenApplyCompleter<T>> consumers;

  @CalledFromNative
  public CompletableFuture() {
    this.consumers = new ArrayList<>();
  }

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

  @CalledFromNative
  public synchronized boolean complete(T result) {
    if (completed) return false;

    this.result = result;
    this.completed = true;

    notifyAll();

    for (ThenApplyCompleter<T> completer : this.consumers) {
      completer.complete.accept(result);
    }

    return true;
  }

  @CalledFromNative
  public synchronized boolean completeExceptionally(Throwable throwable) {
    if (completed) return false;

    if (throwable == null) {
      throwable = new AssertionError("Future failed, but no exception provided");
    }

    this.exception = throwable;
    this.completed = true;

    notifyAll();

    for (ThenApplyCompleter<T> completer : this.consumers) {
      completer.completeExceptionally.accept(throwable);
    }

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

  /**
   * Returns a future that will complete with the applied function applied to this future's
   * completion value.
   *
   * <p>If this future completes exceptionally, the exception will be propagated to the returned
   * future. If this future completes normally but the applied function throws, the returned future
   * will complete exceptionally with the thrown exception.
   */
  public <U> CompletableFuture<U> thenApply(Function<? super T, ? extends U> fn) {
    return this.addChainedFuture(
        (CompletableFuture<U> future, T value) -> {
          U output;
          try {
            output = fn.apply(value);
          } catch (Exception e) {
            future.completeExceptionally(e);
            return;
          }
          future.complete(output);
        },
        CompletableFuture::completeExceptionally);
  }

  /**
   * Returns a future that will complete with the completion result of the future produced by
   * applying a function to this future's completion value.
   *
   * <p>If this future completes exceptionally, the exception will be propagated to the returned
   * future. If this future completes normally but the applied function throws, the returned future
   * will complete exceptionally with the thrown exception. If the future produced by function
   * application completes exceptionally, its error value will be propagated to the returned future.
   */
  public <U> CompletableFuture<U> thenCompose(
      Function<? super T, ? extends CompletableFuture<U>> fn) {
    return this.addChainedFuture(
        (CompletableFuture<U> future, T value) -> {
          CompletableFuture<? extends U> output;
          try {
            output = fn.apply(value);
          } catch (Exception e) {
            future.completeExceptionally(e);
            return;
          }
          output.addCompleter(
              new ThenApplyCompleter<>(future::complete, future::completeExceptionally));
        },
        CompletableFuture::completeExceptionally);
  }

  /**
   * Returns a future of the same type that will execute an action when the original future
   * completes, successfully or not.
   *
   * <p>The action will be invoked with (value, null) for successful completion of the source
   * future, and (null, throwable) otherwise. If the source future completes exceptionally, the
   * exception will be propagated to the returned future after executing the provided action. Any
   * exceptions thrown by action itself are ignored in this case. If the source future succeeds but
   * provided action throws an exception, this exception will be used to complete the resulting
   * future exceptionally.
   */
  public CompletableFuture<T> whenComplete(BiConsumer<? super T, Throwable> fn) {
    return this.addChainedFuture(
        (CompletableFuture<T> future, T value) -> {
          try {
            fn.accept(value, null);
          } catch (Exception e) {
            future.completeExceptionally(e);
            return;
          }
          future.complete(value);
        },
        (CompletableFuture<T> future, Throwable throwable) -> {
          try {
            fn.accept(null, throwable);
          } catch (Exception e) {
            // Ignore the accept exception, and "re-throw" the original one
            future.completeExceptionally(throwable);
            return;
          }
          future.completeExceptionally(throwable);
        });
  }

  private <U> CompletableFuture<U> addChainedFuture(
      BiConsumer<CompletableFuture<U>, T> complete,
      BiConsumer<CompletableFuture<U>, Throwable> completeExceptionally) {
    CompletableFuture<U> future = new CompletableFuture<>();
    ThenApplyCompleter<T> completer =
        new ThenApplyCompleter<T>(
            (T value) -> complete.accept(future, value),
            (Throwable exception) -> completeExceptionally.accept(future, exception));
    this.addCompleter(completer);
    return future;
  }

  private void addCompleter(ThenApplyCompleter<T> completer) {
    T result;
    Throwable exception;
    synchronized (this) {
      if (!this.completed) {
        this.consumers.add(completer);
        return;
      }
      result = this.result;
      exception = this.exception;
    }

    // If this future has already completed, perform the appropriate action now.
    // This is done outside of the synchronized block to prevent deadlocks and
    // holding the lock for a potentially long period.
    if (exception != null) {
      completer.completeExceptionally.accept(exception);
    } else {
      completer.complete.accept(result);
    }
  }

  private static class ThenApplyCompleter<T> {
    private ThenApplyCompleter(
        Consumer<? super T> complete, Consumer<Throwable> completeExceptionally) {
      this.complete = complete;
      this.completeExceptionally = completeExceptionally;
    }

    private Consumer<? super T> complete;
    private Consumer<Throwable> completeExceptionally;
  }
}
