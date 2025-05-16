//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
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
  private boolean cancelled;
  private T result;
  private Throwable exception;
  private List<ThenApplyCompleter<T>> consumers;

  // This is an immutable, unmodifiable sentinel list used to mark that the consumers member
  //   is invalidated after the future is completed.
  private final List<ThenApplyCompleter<T>> INVALIDATED_LIST = Collections.emptyList();

  private Optional<TokioAsyncContext> runtime = Optional.empty();
  private Optional<Long> cancellationId = Optional.empty();

  public CompletableFuture() {
    this.consumers = new ArrayList<>();
  }

  @CalledFromNative
  void setCancellationId(long cancellationId) {
    this.cancellationId = Optional.of(cancellationId);
  }

  public CompletableFuture<T> makeCancelable(TokioAsyncContext context) {
    this.runtime = Optional.of(context);
    return this;
  }

  @Override
  public boolean cancel(boolean mayInterruptIfRunning) {
    if (!mayInterruptIfRunning) {
      // The underlying Rust futures start immediately, so if
      // we can't interrupt them, we can't cancel them.
      return false;
    }

    Throwable throwable = new CancellationException("Future was canceled");
    final List<ThenApplyCompleter<T>> consumers;

    synchronized (this) {
      if (completed || cancelled) return false;

      if (!runtime.isPresent() || !cancellationId.isPresent()) {
        return false;
      }

      runtime
          .get()
          .guardedRun(
              (nativeContextHandle) ->
                  Native.TokioAsyncContext_cancel(nativeContextHandle, cancellationId.get()));

      // Capture consumers before calling completeExceptionally(), because:
      //   - we will need to notify them manually *after* releasing the lock
      //   - completeExceptionally() will invalidate the consumers list
      consumers = this.consumers;
      completeExceptionally(throwable, false);

      // completeExceptionally() will set completed = true, so we only need to set cancelled = true
      cancelled = true;
    }

    // Manually notify all the consumers that the future was canceled.
    // We do this outside of the synchronized block to avoid deadlocks.
    for (ThenApplyCompleter<T> completer : consumers) {
      completer.completeExceptionally.accept(throwable);
    }

    return true;
  }

  @Override
  public synchronized boolean isCancelled() {
    return cancelled;
  }

  @Override
  public synchronized boolean isDone() {
    return completed;
  }

  @CalledFromNative
  public boolean complete(T result) {
    final List<ThenApplyCompleter<T>> consumers;

    synchronized (this) {
      if (completed || cancelled) return false;

      this.result = result;
      this.completed = true;

      consumers = this.consumers;
      this.consumers = INVALIDATED_LIST;

      notifyAll();
    }

    // We execute the completion handlers after releasing our lock to prevent
    //   deadlocks if e.g. any consumers require locks of their own that they
    //   only release after some other operation of ours that requires our
    //   lock completes.
    // We actually saw this happen in the field on Android before.
    for (ThenApplyCompleter<T> completer : consumers) {
      completer.complete.accept(result);
    }

    return true;
  }

  @CalledFromNative
  public boolean completeExceptionally(Throwable throwable) {
    return completeExceptionally(throwable, true);
  }

  private boolean completeExceptionally(Throwable throwable, boolean notifyConsumers) {
    final List<ThenApplyCompleter<T>> consumers;

    synchronized (this) {
      if (completed || cancelled) return false;

      if (throwable == null) {
        throwable = new AssertionError("Future failed, but no exception provided");
      }

      this.exception = throwable;
      this.completed = true;

      consumers = this.consumers;
      this.consumers = INVALIDATED_LIST;

      notifyAll();
    }

    if (notifyConsumers) {
      // We execute the completion handlers after releasing our lock to prevent
      //   deadlocks if e.g. any consumers require locks of their own that they
      //   only release after some other operation of ours that requires our
      //   lock completes.
      // We actually saw this happen in the field on Android before.
      for (ThenApplyCompleter<T> completer : consumers) {
        completer.completeExceptionally.accept(throwable);
      }
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
   *
   * <p><strong>Note:</strong> Unlike the standard CompletableFuture implementation, cancellation
   * propagates both downstream and upstream. If this future or the returned future is cancelled,
   * all futures in the chain will be cancelled.
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
   *
   * <p><strong>Note:</strong> Unlike the standard CompletableFuture implementation, cancellation
   * propagates both downstream and upstream. If this future or the returned future is cancelled,
   * all futures in the chain will be cancelled.
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
   *
   * <p><strong>Note:</strong> Unlike the standard CompletableFuture implementation, cancellation
   * propagates both downstream and upstream. If this future or the returned future is cancelled,
   * all futures in the chain will be cancelled.
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
    if (runtime.isPresent() && cancellationId.isPresent()) {
      future.setCancellationId(cancellationId.get());
      future.makeCancelable(runtime.get());
    }
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
      // This check is load bearing for thread safety.
      //
      // CompletableFuture's complete() and completeExceptionally() methods set
      //   completed = true to indicate that the future is complete, the callbacks
      //   have been or are currently being called, and that this.consumers should
      //   no longer be modified. They do so in a synchronized block, so there is a
      //   happens-before relationship in the Java Memory Model between this.completed
      //   being set, and this.consumers being rendered invalid, which will protect us
      //   since we are in a synchronized block synchronized on the same lock.
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
