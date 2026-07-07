/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.libsignal.internal

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.Test
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.fail

class StreamTest {
  private fun wrapTestStream(
    nativeHandle: ObjectHandle,
    cancelled: AtomicBoolean? = null,
  ): Flow<String> {
    // It's not very efficient to give each stream its own tokio runtime,
    // but that's fine for testing.
    val asyncContext = TokioAsyncContext()
    return wrapStream(
      asyncContext,
      object : NativeHandleGuard.SimpleOwner(nativeHandle) {
        override fun release(nativeHandle: ObjectHandle) {
          NativeTesting.TestStream_Destroy(nativeHandle)
        }
      },
      pull = { asyncRuntime, stream ->
        asyncRuntime
          .guardedMap { asyncRuntime ->
            stream
              .guardedMap { stream ->
                NativeTesting.TESTING_BulkPullFromStream_NextChunk(asyncRuntime, stream)
              }
          }.thenApply {
            val result = it as TestStreamChunk
            Pair(result.chunk, result.termination)
          }
      },
      convertItem = { it },
      cancel = {
        it.guardedRun(NativeTesting::TESTING_BulkPullFromStream_Cancel)
        cancelled?.set(true)
      },
    )
  }

  @Test
  fun testStreaming() =
    runTest {
      val contents = arrayOf("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")

      @Suppress("UNCHECKED_CAST")
      val stream =
        wrapTestStream(NativeTesting.TESTING_BulkPullFromStream_New(contents as Array<Object>, false))
      val received = stream.toList()
      assertEquals<List<String>>(received, contents.toList())
    }

  @Test
  fun testStreamingWithError() =
    runTest {
      val contents = arrayOf("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")

      @Suppress("UNCHECKED_CAST")
      val stream =
        wrapTestStream(NativeTesting.TESTING_BulkPullFromStream_New(contents as Array<Object>, true))
      val received = mutableListOf<String>()
      try {
        stream.collect {
          received += it
        }
        fail("should have thrown an error")
      } catch (e: IllegalArgumentException) {
        assertEquals(e.message, "error")
      }
      assertEquals<List<String>>(received, contents.toList())
    }

  @Test
  fun testStreamingWithCancellation() =
    runTest {
      val contents = arrayOf("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
      val cancelled = AtomicBoolean()

      @Suppress("UNCHECKED_CAST")
      val stream =
        wrapTestStream(NativeTesting.TESTING_BulkPullFromStream_New(contents as Array<Object>, true), cancelled)
      val received = mutableListOf<String>()
      assertFailsWith<CancellationException> {
        coroutineScope {
          stream.collect {
            received += it
            if (received.size >= 3) {
              cancel()
            }
          }
        }
      }
      assertEquals(received, listOf("a", "b", "c"))
      assert(cancelled.get(), { "cancel callback was not invoked" })
    }
}
