//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import static org.junit.Assert.*;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;
import java.util.function.Function;
import org.junit.Test;

public class CompletableFutureTest {
  private class CountingFunction<T, U> implements Function<T, U> {
    public CountingFunction(Function<T, U> f) {
      this.f = f;
    }

    public U apply(T value) {
      this.applicationCount++;
      return this.f.apply(value);
    }

    public long getApplicationCount() {
      return this.applicationCount;
    }

    private long applicationCount = 0;
    private Function<T, U> f;
  }

  @Test
  public void testInitialState() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    assertFalse(future.isDone());
    assertFalse(future.isCancelled());
  }

  @Test
  public void testTimeout() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    assertThrows(TimeoutException.class, () -> future.get(1, TimeUnit.MILLISECONDS));
  }

  @Test
  public void testSuccess() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    future.complete(42);
    assertTrue(future.isDone());
    assertFalse(future.isCancelled());
    assertEquals(42, (int) future.get());
    assertEquals(42, (int) future.get(1, TimeUnit.MILLISECONDS));
  }

  @Test
  public void testFailure() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    Exception exception = new RuntimeException("oh no");
    future.completeExceptionally(exception);
    assertTrue(future.isDone());
    assertFalse(future.isCancelled());
    ExecutionException e = assertThrows(ExecutionException.class, () -> future.get());
    assertEquals(exception, e.getCause());
  }

  @Test
  public void testThenApplySuccess() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    CompletableFuture<Boolean> chained = future.thenApply((Integer i) -> (i == 0));
    assertFalse(chained.isDone());
    future.complete(21);
    assertTrue(chained.isDone());
    assertEquals(false, chained.get());
  }

  @Test
  public void testThenApplyFailure() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    CompletableFuture<Boolean> chained = future.thenApply((Integer i) -> (i == 0));
    Exception exception = new RuntimeException("error!");
    assertFalse(chained.isDone());
    future.completeExceptionally(exception);

    assertTrue(chained.isDone());
    ExecutionException e = assertThrows(ExecutionException.class, () -> chained.get());
    assertEquals(exception, e.getCause());
  }

  @Test
  public void testThenApplyFunctionThrows() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    RuntimeException exception = new RuntimeException("error!");
    CompletableFuture<Boolean> chained =
        future.thenApply(
            (Integer i) -> {
              throw exception;
            });

    assertFalse(chained.isDone());
    future.complete(21);

    assertTrue(chained.isDone());
    ExecutionException e = assertThrows(ExecutionException.class, () -> chained.get());
    assertEquals(exception, e.getCause());
  }

  @Test
  public void testThenApplyAfterCompletion() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    future.complete(21);
    CompletableFuture<Boolean> chained = future.thenApply((Integer i) -> (i == 0));
    assertTrue(chained.isDone());
    assertEquals(false, chained.get());
  }

  @Test
  public void testThenApplyAfterExceptionalCompletion() {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    Exception exception = new RuntimeException("error!");
    future.completeExceptionally(exception);
    CompletableFuture<Boolean> chained = future.thenApply((Integer i) -> (i == 0));
    assertTrue(chained.isDone());
    ExecutionException e = assertThrows(ExecutionException.class, () -> chained.get());
    assertEquals(exception, e.getCause());
  }

  @Test
  public void testThenApplyAfterCompletionFunctionThrows() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    future.complete(21);

    RuntimeException exception = new RuntimeException("error!");
    CompletableFuture<Boolean> chained =
        future.thenApply(
            (Integer i) -> {
              throw exception;
            });

    assertTrue(chained.isDone());
    ExecutionException e = assertThrows(ExecutionException.class, () -> chained.get());
    assertEquals(exception, e.getCause());
  }

  @Test
  public void testThenApplyAfterExceptionalCompletionFunctionThrows() {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    Exception exception = new RuntimeException("future error!");
    future.completeExceptionally(exception);

    CompletableFuture<Boolean> chained =
        future.thenApply(
            (Integer i) -> {
              throw new RuntimeException("apply function error!");
            });
    assertTrue(chained.isDone());

    ExecutionException e = assertThrows(ExecutionException.class, () -> chained.get());
    // The function application error never gets thrown.
    assertEquals(exception, e.getCause());
  }

  @Test
  public void testThenApplyOnceFirstCompletionOnly() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    CountingFunction<Integer, Boolean> function = new CountingFunction<>((Integer i) -> (i == 0));
    CompletableFuture<Boolean> chained = future.thenApply(function);

    assertFalse(chained.isDone());
    future.complete(55);

    assertTrue(chained.isDone());
    future.complete(33);
    future.complete(0);

    assertEquals(false, chained.get());
    assertEquals(function.getApplicationCount(), 1);
  }

  @Test
  public void testThenComposeSuccess() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    CompletableFuture<Boolean> chainedResult = new CompletableFuture<>();
    CountingFunction<Integer, CompletableFuture<Boolean>> counting =
        new CountingFunction<>((Integer i) -> chainedResult);

    CompletableFuture<Boolean> chained = future.thenCompose(counting);
    assertFalse(chained.isDone());
    assertEquals(counting.getApplicationCount(), 0);

    future.complete(21);
    assertEquals(counting.getApplicationCount(), 1);
    assertFalse(chained.isDone());

    chainedResult.complete(true);
    assertTrue(chained.isDone());
    assertEquals(true, chained.get());
  }

  @Test
  public void testThenComposeFailure() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    CompletableFuture<Boolean> chainedResult = new CompletableFuture<>();
    CountingFunction<Integer, CompletableFuture<Boolean>> counting =
        new CountingFunction<>((Integer i) -> chainedResult);

    CompletableFuture<Boolean> chained = future.thenCompose(counting);
    Exception exception = new RuntimeException("error!");

    assertFalse(chained.isDone());
    assertEquals(counting.getApplicationCount(), 0);
    future.completeExceptionally(exception);

    assertTrue(chained.isDone());
    assertEquals(counting.getApplicationCount(), 0);
    ExecutionException e = assertThrows(ExecutionException.class, () -> chained.get());
    assertEquals(exception, e.getCause());
  }

  @Test
  public void testThenComposeAfterCompletion() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();

    future.complete(21);

    CompletableFuture<Boolean> chainedResult = new CompletableFuture<>();
    CountingFunction<Integer, CompletableFuture<Boolean>> counting =
        new CountingFunction<>((Integer i) -> chainedResult);
    CompletableFuture<Boolean> chained = future.thenCompose(counting);

    assertEquals(counting.getApplicationCount(), 1);
    assertFalse(chained.isDone());

    chainedResult.complete(false);

    assertTrue(chained.isDone());
    assertEquals(false, chained.get());
  }

  @Test
  public void testThenComposeAfterExceptionalCompletion() {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    Exception exception = new RuntimeException("error!");
    future.completeExceptionally(exception);

    CompletableFuture<Boolean> chainedResult = new CompletableFuture<>();
    CountingFunction<Integer, CompletableFuture<Boolean>> counting =
        new CountingFunction<>((Integer i) -> chainedResult);
    CompletableFuture<Boolean> chained = future.thenCompose(counting);

    assertTrue(chained.isDone());
    assertEquals(counting.getApplicationCount(), 0);
    ExecutionException e = assertThrows(ExecutionException.class, () -> chained.get());
    assertEquals(exception, e.getCause());
  }

  @Test
  public void testThenComposeAfterCompletionFunctionThrows() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    future.complete(21);

    RuntimeException exception = new RuntimeException("error!");
    CompletableFuture<Boolean> chainedResult = new CompletableFuture<>();
    CountingFunction<Integer, CompletableFuture<Boolean>> counting =
        new CountingFunction<>(
            (Integer i) -> {
              throw exception;
            });
    CompletableFuture<Boolean> chained = future.thenCompose(counting);

    assertTrue(chained.isDone());
    assertEquals(counting.getApplicationCount(), 1);
    ExecutionException e = assertThrows(ExecutionException.class, () -> chained.get());
    assertEquals(exception, e.getCause());
  }

  @Test
  public void testThenComposeAfterExceptionalCompletionFunctionThrows() {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    Exception exception = new RuntimeException("future error!");
    future.completeExceptionally(exception);

    CompletableFuture<Boolean> chained =
        future.thenApply(
            (Integer i) -> {
              throw new RuntimeException("apply function error!");
            });
    assertTrue(chained.isDone());

    ExecutionException e = assertThrows(ExecutionException.class, () -> chained.get());
    // The function application error never gets thrown.
    assertEquals(exception, e.getCause());
  }

  @Test
  public void testThenComposeProducedFutureCompletesExceptionally() {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    CompletableFuture<Boolean> chainedResult = new CompletableFuture<>();
    CountingFunction<Integer, CompletableFuture<Boolean>> counting =
        new CountingFunction<>((Integer i) -> chainedResult);
    CompletableFuture<Boolean> chained = future.thenCompose(counting);

    future.complete(21);
    assertEquals(counting.getApplicationCount(), 1);
    assertFalse(chained.isDone());

    Exception exception = new RuntimeException("future error!");
    chainedResult.completeExceptionally(exception);

    ExecutionException e = assertThrows(ExecutionException.class, () -> chained.get());
    assertEquals(exception, e.getCause());
  }

  @Test
  public void testThenComposeProducedFutureCompletesExceptionallyAfterSuccess() {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    future.complete(21);

    CompletableFuture<Boolean> chainedResult = new CompletableFuture<>();
    CountingFunction<Integer, CompletableFuture<Boolean>> counting =
        new CountingFunction<>((Integer i) -> chainedResult);
    CompletableFuture<Boolean> chained = future.thenCompose(counting);

    assertEquals(counting.getApplicationCount(), 1);
    assertFalse(chained.isDone());

    Exception exception = new RuntimeException("future error!");
    chainedResult.completeExceptionally(exception);

    ExecutionException e = assertThrows(ExecutionException.class, () -> chained.get());
    assertEquals(exception, e.getCause());
  }

  // These multi-threaded tests are inherently racy in whether they actually have one thread wait()
  // and the other notify(). The observable behavior shouldn't be different, though.

  @Test
  public void testSuccessMultiThreaded() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();

    new Thread(
            () -> {
              try {
                Thread.sleep(200);
              } catch (InterruptedException e) {
              }
              future.complete(42);
            })
        .start();

    assertEquals(42, (int) future.get());
  }

  @Test
  public void testFailureMultiThreaded() throws Exception {
    CompletableFuture<Integer> future = new CompletableFuture<>();
    Exception exception = new RuntimeException("oh no");

    new Thread(
            () -> {
              try {
                Thread.sleep(200);
              } catch (InterruptedException e) {
              }
              future.completeExceptionally(exception);
            })
        .start();

    ExecutionException e = assertThrows(ExecutionException.class, () -> future.get());
    assertEquals(exception, e.getCause());
  }

  private class CountingBiConsumer<T, U> implements BiConsumer<T, U> {
    public int acceptCalls = 0;
    public int successes = 0;
    public int failures = 0;
    private BiConsumer<T, U> consumer = (t, u) -> {};

    public CountingBiConsumer() {}

    public CountingBiConsumer(BiConsumer<T, U> sideEffects) {
      this.consumer = sideEffects;
    }

    @Override
    public void accept(T t, U u) {
      this.acceptCalls += 1;
      this.successes += t == null ? 0 : 1;
      this.failures += u == null ? 0 : 1;
      this.consumer.accept(t, u);
    }
  }

  @Test
  public void testWhenCompleteSuccess() throws Exception {
    var future = new CompletableFuture<Integer>();
    var consumer = new CountingBiConsumer<Integer, Throwable>();
    var chained = future.whenComplete(consumer);

    assertFalse(chained.isDone());

    future.complete(42);
    assertTrue(chained.isDone());
    assertEquals(42, chained.get().intValue());
    assertEquals(1, consumer.acceptCalls);
    assertEquals(1, consumer.successes);
    assertEquals(0, consumer.failures);
  }

  @Test
  public void testWhenCompleteFailure() throws Exception {
    var future = new CompletableFuture<Integer>();
    var consumer = new CountingBiConsumer<Integer, Throwable>();
    var chained = future.whenComplete(consumer);

    assertFalse(chained.isDone());

    var exception = new RuntimeException();
    future.completeExceptionally(exception);
    assertTrue(chained.isDone());
    assertEquals(1, consumer.acceptCalls);
    assertEquals(0, consumer.successes);
    assertEquals(1, consumer.failures);
    try {
      chained.get();
    } catch (ExecutionException ex) {
      assertEquals(exception, ex.getCause());
    }
  }

  @Test
  public void testWhenCompleteFailureAfterSuccess() throws Exception {
    var future = new CompletableFuture<Integer>();
    var exception = new RuntimeException();
    var consumer =
        new CountingBiConsumer<Integer, Throwable>(
            (t, u) -> {
              throw exception;
            });
    var chained = future.whenComplete(consumer);

    assertFalse(chained.isDone());

    future.complete(42);
    assertTrue(chained.isDone());
    assertEquals(1, consumer.acceptCalls);
    assertEquals(1, consumer.successes);
    assertEquals(0, consumer.failures);
    try {
      chained.get();
    } catch (ExecutionException ex) {
      assertEquals(exception, ex.getCause());
    }
  }

  @Test
  public void testWhenCompleteFailureAfterFailure() throws Exception {
    var future = new CompletableFuture<Integer>();
    var futureException = new RuntimeException();
    var callbackException = new RuntimeException();
    var consumer =
        new CountingBiConsumer<Integer, Throwable>(
            (t, u) -> {
              throw callbackException;
            });
    var chained = future.whenComplete(consumer);

    assertFalse(chained.isDone());

    future.completeExceptionally(futureException);
    assertTrue(chained.isDone());
    assertEquals(1, consumer.acceptCalls);
    assertEquals(0, consumer.successes);
    assertEquals(1, consumer.failures);
    try {
      chained.get();
    } catch (ExecutionException ex) {
      assertEquals(futureException, ex.getCause());
      assertNotEquals(callbackException, ex.getCause());
    }
  }
}
