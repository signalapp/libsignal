//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Compares the basic behavior of libsignal's CompletableFuture with the JDK's.
 *
 * <p>Run as a "server" test to leave it out of the emulator tests, since the standard
 * CompletableFuture isn't available until API 24.
 */
@RunWith(Parameterized.class)
public class CompletableFutureJDKCompatTest {
  /** Helper type to ensure we get a unique Future for every test. */
  private record Input(
      Future<Integer> future,
      Function<Integer, Boolean> complete,
      Function<Throwable, Boolean> completeExceptionally) {}

  @Parameters(name = "{0}")
  public static Object[][] parameters() {
    return new Object[][] {
      {
        "JDK",
        (Supplier)
            () -> {
              final var jdkFuture = new java.util.concurrent.CompletableFuture<Integer>();
              return new Input(jdkFuture, jdkFuture::complete, jdkFuture::completeExceptionally);
            }
      },
      {
        "libsignal",
        (Supplier)
            () -> {
              final var libsignalFuture = new CompletableFuture<Integer>();
              return new Input(
                  libsignalFuture,
                  libsignalFuture::complete,
                  libsignalFuture::completeExceptionally);
            }
      },
    };
  }

  private final Input params;

  public CompletableFutureJDKCompatTest(String _name, Supplier<Input> params) {
    this.params = params.get();
  }

  @Test
  public void testInitialState() throws Exception {
    assertFalse(params.future.isDone());
    assertFalse(params.future.isCancelled());
  }

  @Test
  public void testTimeout() throws Exception {
    assertThrows(TimeoutException.class, () -> params.future.get(1, TimeUnit.MILLISECONDS));
  }

  @Test
  public void testSuccess() throws Exception {
    assertTrue(params.complete.apply(42));
    assertTrue(params.future.isDone());
    assertFalse(params.future.isCancelled());
    assertEquals(42, (int) params.future.get());
    assertEquals(42, (int) params.future.get(1, TimeUnit.MILLISECONDS));
  }

  @Test
  public void testFailure() throws Exception {
    Exception exception = new RuntimeException("oh no");
    assertTrue(params.completeExceptionally.apply(exception));
    assertTrue(params.future.isDone());
    assertFalse(params.future.isCancelled());
    ExecutionException e = assertThrows(ExecutionException.class, () -> params.future.get());
    assertSame(exception, e.getCause());
  }

  @Test
  public void testCancelWithoutInterrupting() throws Exception {
    assertTrue(params.future.cancel(false));
    assertTrue(params.future.isDone());
    assertTrue(params.future.isCancelled());
    assertThrows(CancellationException.class, () -> params.future.get());
  }

  @Test
  public void testCancelWithInterrupting() throws Exception {
    assertTrue(params.future.cancel(true));
    assertTrue(params.future.isDone());
    assertTrue(params.future.isCancelled());
    assertThrows(CancellationException.class, () -> params.future.get());
  }

  @Test
  public void testManualCancellation() throws Exception {
    assertTrue(params.completeExceptionally.apply(new CancellationException()));
    assertTrue(params.future.isDone());
    assertTrue(params.future.isCancelled());
    assertThrows(CancellationException.class, () -> params.future.get());
  }

  @Test
  public void testCompleteAfterComplete() throws Exception {
    assertTrue(params.complete.apply(42));
    assertFalse(params.complete.apply(43));
    assertTrue(params.future.isDone());
    assertFalse(params.future.isCancelled());
    assertEquals(42, (int) params.future.get());
  }

  @Test
  public void testExceptionAfterComplete() throws Exception {
    assertTrue(params.complete.apply(42));
    assertFalse(params.completeExceptionally.apply(new RuntimeException("oh no")));
    assertTrue(params.future.isDone());
    assertFalse(params.future.isCancelled());
    assertEquals(42, (int) params.future.get());
  }

  @Test
  public void testCancelAfterComplete() throws Exception {
    assertTrue(params.complete.apply(42));
    assertFalse(params.future.cancel(true));
    assertTrue(params.future.isDone());
    assertFalse(params.future.isCancelled());
    assertEquals(42, (int) params.future.get());
  }

  @Test
  public void testCompleteAfterException() throws Exception {
    Exception exception = new RuntimeException("oh no");
    assertTrue(params.completeExceptionally.apply(exception));
    assertFalse(params.complete.apply(42));
    assertTrue(params.future.isDone());
    assertFalse(params.future.isCancelled());
    ExecutionException e = assertThrows(ExecutionException.class, () -> params.future.get());
    assertSame(exception, e.getCause());
  }

  @Test
  public void testExceptionAfterException() throws Exception {
    Exception exception = new RuntimeException("oh no");
    assertTrue(params.completeExceptionally.apply(exception));
    assertFalse(params.completeExceptionally.apply(new RuntimeException("even worse")));
    assertTrue(params.future.isDone());
    assertFalse(params.future.isCancelled());
    ExecutionException e = assertThrows(ExecutionException.class, () -> params.future.get());
    assertSame(exception, e.getCause());
  }

  @Test
  public void testCancelAfterException() throws Exception {
    Exception exception = new RuntimeException("oh no");
    assertTrue(params.completeExceptionally.apply(exception));
    assertFalse(params.future.cancel(true));
    assertTrue(params.future.isDone());
    assertFalse(params.future.isCancelled());
    ExecutionException e = assertThrows(ExecutionException.class, () -> params.future.get());
    assertSame(exception, e.getCause());
  }

  @Test
  public void testCompleteAfterCancel() throws Exception {
    assertTrue(params.future.cancel(true));
    assertFalse(params.complete.apply(42));
    assertTrue(params.future.isDone());
    assertTrue(params.future.isCancelled());
    assertThrows(CancellationException.class, () -> params.future.get());
  }

  @Test
  public void testExceptionAfterCancel() throws Exception {
    assertTrue(params.future.cancel(true));
    assertFalse(params.completeExceptionally.apply(new RuntimeException("oh no")));
    assertTrue(params.future.isDone());
    assertTrue(params.future.isCancelled());
    assertThrows(CancellationException.class, () -> params.future.get());
  }

  @Test
  public void testCancelAfterCancel() throws Exception {
    assertTrue(params.future.cancel(true));
    assertTrue(params.future.cancel(true)); // This is different from the complete*() APIs!
    assertTrue(params.future.isDone());
    assertTrue(params.future.isCancelled());
    assertThrows(CancellationException.class, () -> params.future.get());
  }
}
