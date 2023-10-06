//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import static org.junit.Assert.*;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.Test;

public class FutureTest {
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
  public void testSuccessFromRust() throws Exception {
    Future<Integer> future = Native.TESTING_FutureSuccess(1, 21);
    assertEquals(42, (int) future.get());
  }

  @Test
  public void testFailureFromRust() throws Exception {
    Future<Integer> future = Native.TESTING_FutureFailure(1, 21);
    ExecutionException e = assertThrows(ExecutionException.class, () -> future.get());
    assertTrue(e.getCause() instanceof IllegalArgumentException);
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
}
