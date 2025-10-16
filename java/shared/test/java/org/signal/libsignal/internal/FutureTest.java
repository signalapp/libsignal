//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import static org.junit.Assert.*;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
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

  @Test(timeout = 5000)
  public void testFutureThrowsInvalidException() throws Exception {
    Future future = NativeTesting.TESTING_FutureThrowsPoisonErrorType(ioRuntime);
    ExecutionException e = assertThrows(ExecutionException.class, () -> future.get());
    assertTrue(e.getCause() instanceof AssertionError);
    // Check the whole message to make sure it includes both the original error and the failure to
    // convert it to an exception. (TestingError just makes that feel especially confusing!)
    assertTrue(
        e.getCause().getMessage(),
        e.getCause()
            .getMessage()
            .startsWith(
                "failed to convert error \"TestingError(org.signal.libsignal.internal.GuaranteedNonexistentException)\": "
                    + "exception in method call 'org.signal.libsignal.internal.GuaranteedNonexistentException': exception "));
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
      assertThrows(CancellationException.class, () -> testFuture.get());
      assertTrue(testFuture.isCancelled());
    } else {
      // The future completed before we could cancel it.
      // Oppurtunitically, let's just check that the future completed as expected.
      try {
        assertEquals(63, (int) testFuture.get());
        assertFalse(testFuture.isCancelled());
      } catch (ExecutionException | InterruptedException e) {
        fail("testFuture.get() threw an unexpected exception: " + e.getMessage());
      }
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
    org.signal.libsignal.internal.CompletableFuture<Void> testFuture =
        context
            .guardedMap(
                (nativeContextHandle) ->
                    counter.guardedMap(
                        counterHandle ->
                            NativeTesting.TESTING_FutureIncrementOnCancel(
                                nativeContextHandle, counterHandle)))
            .makeCancelable(context);
    assertTrue(testFuture.cancel(true));
    assertThrows(CancellationException.class, () -> testFuture.get());
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

  private static class TestingValueHolder extends NativeHandleGuard.SimpleOwner {
    TestingValueHolder(long nativeHandle) {
      super(nativeHandle);
    }

    @Override
    protected void release(long nativeHandle) {
      NativeTesting.TestingValueHolder_Destroy(nativeHandle);
    }
  }

  // Make sure we don't hang if for some reason finalization never happens.
  @Test(timeout = 10_000)
  public void testBridgeHandleLifetime() throws Exception {
    final int INITIAL = 0x10101010;

    TokioAsyncContext context = new TokioAsyncContext();
    var handleBeingTested =
        new NativeHandleGuard.SimpleOwner(NativeTesting.TestingValueHolder_New(INITIAL)) {
          CountDownLatch latch = new CountDownLatch(1);

          @Override
          protected void release(long nativeHandle) {
            NativeTesting.TestingValueHolder_Destroy(nativeHandle);
            latch.countDown();
          }
        };
    var latch = handleBeingTested.latch;
    var semaphore =
        new NativeHandleGuard.SimpleOwner(NativeTesting.TestingSemaphore_New(0)) {
          @Override
          protected void release(long nativeHandle) {
            NativeTesting.TestingSemaphore_Destroy(nativeHandle);
          }
        };

    CompletableFuture<Integer> future =
        handleBeingTested.guardedMap(
            handle ->
                semaphore.guardedMap(
                    semaphoreHandle ->
                        context.guardedMap(
                            nativeContextHandle ->
                                NativeTesting.TESTING_AcquireSemaphoreAndGet(
                                    nativeContextHandle, semaphoreHandle, handle))));

    handleBeingTested = null;

    do {
      System.gc();
      System.runFinalization();
    } while (!latch.await(100, TimeUnit.MILLISECONDS));

    semaphore.guardedRun(
        semaphoreHandle -> NativeTesting.TestingSemaphore_AddPermits(semaphoreHandle, 1));

    int result = future.get();
    assertEquals("memory corrupted", result, INITIAL);
  }

  @Test(timeout = 10_000)
  public void testFutureResultIsNotLeakedEvenWithPermanentJVMAttachedThreads() throws Exception {
    var context =
        new TokioAsyncContext(NativeTesting.TESTING_TokioAsyncContext_NewSingleThreaded());
    context.guardedRun(
        nativeContextHandle ->
            NativeTesting.TESTING_TokioAsyncContext_AttachBlockingThreadToJVMPermanently(
                nativeContextHandle, null));

    var finalizationQueue = new java.lang.ref.ReferenceQueue<byte[]>();
    java.lang.ref.PhantomReference<byte[]> reference;

    {
      int length = 1024;
      CompletableFuture<byte[]> future =
          context.guardedMap(
              nativeContextHandle ->
                  NativeTesting.TESTING_TokioAsyncContext_FutureSuccessBytes(
                      nativeContextHandle, length));
      byte[] result = future.get();
      reference = new java.lang.ref.PhantomReference<>(result, finalizationQueue);
      assertEquals(length, result.length);
      future = null;
      result = null;
    }

    do {
      System.gc();
      System.runFinalization();
    } while (finalizationQueue.remove(100) != reference);
  }
}
