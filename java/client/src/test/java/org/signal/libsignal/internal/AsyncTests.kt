/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.libsignal.internal

import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import java.util.concurrent.CancellationException
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class AsyncTests {
  private var ioRuntime: Long = 0

  @BeforeTest
  fun initIoRuntime() {
    ioRuntime = NativeTesting.TESTING_NonSuspendingBackgroundThreadRuntime_New()
  }

  @AfterTest
  fun destroyIoRuntime() {
    NativeTesting.TESTING_NonSuspendingBackgroundThreadRuntime_Destroy(ioRuntime)
    ioRuntime = 0
  }

  @Test
  fun testSuccessFromRust() = runTest {
    val result = NativeTesting.TESTING_FutureSuccess(ioRuntime, 21).await()
    assertEquals(42, result)
  }

  @Test
  fun testFailureFromRust() = runTest {
    assertFailsWith<IllegalArgumentException> {
      NativeTesting.TESTING_FutureFailure(ioRuntime, 21).await()
    }
  }

  @Test
  fun testFutureOnlyCompletesByCancellation() = runTest(timeout = 5.seconds) {
    val context = TokioAsyncContext()
    val counter =
      object : NativeHandleGuard.SimpleOwner(
        NativeTesting.TESTING_FutureCancellationCounter_Create(0),
      ) {
        override fun release(nativeHandle: Long) {
          NativeTesting.TestingFutureCancellationCounter_Destroy(nativeHandle)
        }
      }
    val testFuture =
      context
        .guardedMap { nativeContextHandle: Long ->
          counter.guardedMap { counterHandle: Long ->
            NativeTesting.TESTING_FutureIncrementOnCancel(
              nativeContextHandle,
              counterHandle,
            )
          }
        }
        .makeCancelable(context)
    assertFailsWith<TimeoutCancellationException> {
      withTimeout(20.milliseconds) { testFuture.await() }
    }
    assertTrue(testFuture.isCancelled)
    assertTrue(testFuture.isDone)
    assertFailsWith<CancellationException> { testFuture.await() }

    // Hangs if the count never gets incremented.
    context
      .guardedMap { nativeContextHandle: Long ->
        counter.guardedMap { counterHandle: Long ->
          NativeTesting.TESTING_FutureCancellationCounter_WaitForCount(
            nativeContextHandle,
            counterHandle,
            1,
          )
        }
      }
      .await()
  }
}
