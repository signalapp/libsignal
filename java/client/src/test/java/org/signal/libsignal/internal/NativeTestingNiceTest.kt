//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal

import org.junit.Test
import org.signal.libsignal.protocol.ServiceId
import java.util.UUID
import kotlin.test.assertEquals

class NativeTestingNiceTest {
  private fun <T> testConversion(
    items: Sequence<T>,
    toString: (T) -> String,
    nativeToString: (T) -> String,
    nativeIdentity: (T) -> T,
  ) {
    for (item in items) {
      assertEquals(toString(item), nativeToString(item))
      assertEquals(item, nativeIdentity(item))
    }
  }

  @Test
  fun string() =
    testConversion(
      listOf("", "abc", "îüéè").asSequence(),
      toString = { it },
      nativeToString = NativeTestingNice::TESTING_conversion_string_identity,
      nativeIdentity = NativeTestingNice::TESTING_conversion_string_identity,
    )

  @Test
  fun bool() =
    testConversion(
      listOf(true, false).asSequence(),
      toString = Any::toString,
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
      toString = Any::toString,
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
      toString = Any::toString,
      nativeToString = NativeTestingNice::TESTING_conversion_u16_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_u16_identity,
    )

  @Test
  fun i32() =
    testConversion(
      (-1024 until 1024).asSequence(),
      toString = Any::toString,
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
}
