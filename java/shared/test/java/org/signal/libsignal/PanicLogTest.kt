/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.libsignal

import org.junit.Assert
import org.junit.ClassRule
import org.junit.Test
import org.junit.function.ThrowingRunnable
import org.signal.libsignal.internal.NativeTesting
import org.signal.libsignal.util.TestLogger
import org.signal.libsignal.util.TestLoggerDecorator
import kotlin.test.assertContains
import kotlin.test.assertEquals

class PanicLogTest {
  companion object {
    @ClassRule
    @JvmField
    val logger = TestLogger()
  }

  @Test
  public fun testPanicsLog() {
    TestLoggerDecorator.logs.set(mutableListOf())
    try {
      Assert.assertThrows(
        AssertionError::class.java,
        ThrowingRunnable {
          @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
          NativeTesting.TESTING_PanicOnBorrowSync("123" as Object)
        },
      )
      val logs = TestLoggerDecorator.logs.get()!!
      assertEquals(1, logs.size)
      assertContains(logs[0].message, "panicked at")
    } finally {
      TestLoggerDecorator.logs.set(null)
    }
  }
}
