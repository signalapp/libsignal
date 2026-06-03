//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal

import org.junit.Test
import kotlin.test.assertEquals

class TestingIntBox(
  handle: ObjectHandle,
) : NativeHandleGuard.SimpleOwner(handle) {
  companion object {
    fun create(value: Int): TestingIntBox = TestingIntBox(NativeTesting.TESTING_TestingIntBox_New(value))
  }

  @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
  fun get(): Int = NativeTesting.TESTING_TestingIntBox_Get(this)

  override fun release(nativeHandle: ObjectHandle) {
    NativeTesting.TestingIntBox_Destroy(nativeHandle)
  }
}

class TypedObjectHandleTest {
  @Test
  fun testTypedObjectHandle() {
    val box = TestingIntBox.create(17)
    assertEquals(17, box.get())
    assertEquals(17, NativeTestingNice.TESTING_TestingIntBox_Get(myIntBox = box))
  }
}
