//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import static org.junit.Assert.*;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class FutureTest {
  long ioRuntime = 0;

  @Before
  public void initIoRuntime() {
    ioRuntime = NativeTesting.TESTING_NonSuspendingBackgroundThreadRuntime_New();
  }

  @After
  public void destroyIoRuntime() {
    NativeTesting.TESTING_NonSuspendingBackgroundThreadRuntime_Destroy(ioRuntime);
    ioRuntime = 0;
  }

  @Test
  public void testSuccessFromRust() throws Exception {
    Future<Integer> future = NativeTesting.TESTING_FutureSuccess(ioRuntime, 21);
    assertEquals(42, (int) future.get());
  }

  @Test
  public void testFailureFromRust() throws Exception {
    Future<Integer> future = NativeTesting.TESTING_FutureFailure(ioRuntime, 21);
    ExecutionException e = assertThrows(ExecutionException.class, () -> future.get());
    assertTrue(e.getCause() instanceof IllegalArgumentException);
  }

  @Test
  public void testFutureThrowsUnloadedException() throws Exception {
    Future future = NativeTesting.TESTING_FutureThrowsCustomErrorType(ioRuntime);
    ExecutionException e = assertThrows(ExecutionException.class, () -> future.get());
    assertTrue(e.getCause() instanceof org.signal.libsignal.internal.TestingException);
  }

  @Test
  public void testFutureFromRustCancel() {
    TokioAsyncContext context = new TokioAsyncContext();
    org.signal.libsignal.internal.CompletableFuture<Integer> testFuture =
        context
            .guardedMap(
                (nativeContextHandle) ->
                    NativeTesting.TESTING_TokioAsyncFuture(nativeContextHandle, 21))
            .makeCancelable(context);
    if (testFuture.cancel(true)) {
      ExecutionException e = assertThrows(ExecutionException.class, () -> testFuture.get());
      assertTrue(
          "Expected CancellationException as cause",
          e.getCause() instanceof java.util.concurrent.CancellationException);
      assertTrue(testFuture.isCancelled());
    }
    assertTrue(testFuture.isDone());
  }

  @Test(timeout = 5000)
  @SuppressWarnings("unchecked")
  public void testFutureOnlyCompletesByCancellation() throws Exception {
    TokioAsyncContext context = new TokioAsyncContext();
    var counter =
        new NativeHandleGuard.SimpleOwner(
            NativeTesting.TESTING_FutureCancellationCounter_Create(0)) {
          @Override
          protected void release(long nativeHandle) {
            NativeTesting.TestingFutureCancellationCounter_Destroy(nativeHandle);
          }
        };
    org.signal.libsignal.internal.CompletableFuture<Integer> testFuture =
        context
            .guardedMap(
                (nativeContextHandle) ->
                    counter.guardedMap(
                        counterHandle ->
                            NativeTesting.TESTING_FutureIncrementOnCancel(
                                nativeContextHandle, counterHandle)))
            .makeCancelable(context);
    assertTrue(testFuture.cancel(true));
    ExecutionException e = assertThrows(ExecutionException.class, () -> testFuture.get());
    assertTrue(
        "Expected CancellationException as cause",
        e.getCause() instanceof java.util.concurrent.CancellationException);
    assertTrue(testFuture.isCancelled());
    assertTrue(testFuture.isDone());

    // Hangs if the count never gets incremented.
    context
        .guardedMap(
            (nativeContextHandle) ->
                counter.guardedMap(
                    counterHandle ->
                        NativeTesting.TESTING_FutureCancellationCounter_WaitForCount(
                            nativeContextHandle, counterHandle, 1)))
        .get();
  }

  @Test
  public void testCapturedStackTraceInException() throws Exception {
    Future future = NativeTesting.TESTING_FutureFailure(ioRuntime, 21);
    ExecutionException e = assertThrows(ExecutionException.class, () -> future.get());

    Throwable actualStackTrace = e.getCause();

    StringWriter sw = new StringWriter();
    actualStackTrace.printStackTrace(new PrintWriter(sw));
    String stackTraceString = sw.toString();

    String expectedMethodName = new Throwable().getStackTrace()[0].getMethodName();
    String expectedClassName = new Throwable().getStackTrace()[0].getClassName();

    String failureMessage =
        "Stack trace should contain the test method "
            + expectedClassName
            + "."
            + expectedMethodName
            + " \n"
            + "Actual stack trace: \n"
            + stackTraceString;

    assertTrue(
        failureMessage,
        actualStackTrace.getStackTrace().length > 0
            && Arrays.stream(actualStackTrace.getStackTrace())
                .anyMatch(
                    element ->
                        element.getClassName().equals(expectedClassName)
                            && element.getMethodName().contains(expectedMethodName)));
  }
}
