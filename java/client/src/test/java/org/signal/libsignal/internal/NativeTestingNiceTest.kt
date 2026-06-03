//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal

import org.junit.Test
import org.signal.libsignal.protocol.ServiceId
import java.util.UUID
import kotlin.io.encoding.Base64
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NativeTestingNiceTest {
  private fun <T> testConversion(
    items: Sequence<T>,
    nativeToString: (T) -> String,
    nativeIdentity: (T) -> T,
    toString: (T) -> String = { it.toString() },
    equality: (T, T) -> Boolean = { a, b -> a == b },
  ) {
    for (item in items) {
      assertEquals(toString(item), nativeToString(item))
      val roundTripped = nativeIdentity(item)
      assertTrue(equality(roundTripped, item), "${toString(item)} != ${toString(roundTripped)}")
    }
  }

  @Test
  fun string() =
    testConversion(
      listOf("", "abc", "îüéè").asSequence(),
      nativeToString = NativeTestingNice::TESTING_conversion_string_identity,
      nativeIdentity = NativeTestingNice::TESTING_conversion_string_identity,
    )

  @Test
  fun bool() =
    testConversion(
      listOf(true, false).asSequence(),
      nativeToString = NativeTestingNice::TESTING_conversion_bool_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_bool_identity,
    )

  @Test
  fun u8() =
    testConversion(
      UByte.MIN_VALUE
        .toInt()
        .rangeTo(UByte.MAX_VALUE.toInt())
        .asSequence(),
      nativeToString = NativeTestingNice::TESTING_conversion_u8_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_u8_identity,
    )

  @Test
  fun u16() =
    testConversion(
      UShort.MIN_VALUE
        .toInt()
        .rangeTo(UShort.MAX_VALUE.toInt())
        .asSequence(),
      nativeToString = NativeTestingNice::TESTING_conversion_u16_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_u16_identity,
    )

  @Test
  fun i32() =
    testConversion(
      (-1024 until 1024).asSequence(),
      nativeToString = NativeTestingNice::TESTING_conversion_i32_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_i32_identity,
    )

  @Test
  fun serviceId() =
    testConversion(
      (0 until 10).asSequence().flatMap {
        val uuid = UUID.nameUUIDFromBytes(it.toString().toByteArray())
        listOf(
          ServiceId.Aci(uuid),
          ServiceId.Pni(uuid),
        ).asSequence()
      },
      toString = ServiceId::toServiceIdString,
      nativeToString = NativeTestingNice::TESTING_conversion_ServiceId_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_ServiceId_identity,
    )

  @Test
  fun data() =
    testConversion(
      (0 until 10).asSequence().map({ Random.nextBytes(1 shl it) }),
      toString = Base64::encode,
      nativeToString = NativeTestingNice::TESTING_conversion_Data_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_Data_identity,
      equality = java.util.Arrays::equals,
    )

  @Test
  fun testAsync() {
    val tokio = TokioAsyncContext()
    for (count in listOf(0, 1, 2, 4, 8, 16, 32, 64, 128, 256)) {
      val data = NativeTestingNice.TESTING_TokioAsyncContext_FutureSuccessBytes(tokio, count).get()
      assertEquals(count, data.size)
    }
  }
}
