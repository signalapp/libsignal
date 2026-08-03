//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal

import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.junit.Test
import org.signal.libsignal.protocol.ServiceId
import java.time.Instant
import java.time.format.DateTimeFormatterBuilder
import java.util.Arrays
import java.util.UUID
import kotlin.io.encoding.Base64
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertIs
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
  fun data32() =
    testConversion(
      sequenceOf(Random.nextBytes(32)),
      toString = Base64::encode,
      nativeToString = NativeTestingNice::TESTING_conversion_Data32_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_Data32_identity,
      equality = java.util.Arrays::equals,
    )

  @Test
  fun data32BridgeVec() =
    testConversion(
      (0 until 8).asSequence().map { count -> (0 until count).map { Random.nextBytes(32) } },
      toString = { it.joinToString("\n", transform = Base64::encode) },
      nativeToString = NativeTestingNice::TESTING_conversion_BridgeVecData32_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_BridgeVecData32_identity,
      equality = { a, b -> a.zip(b).all { (a, b) -> a.contentEquals(b) } },
    )

  @Test
  fun dataU8() =
    testConversion(
      (0 until 10).asSequence().map({ Random.nextBytes(1 shl it) }),
      toString = Base64::encode,
      nativeToString = NativeTestingNice::TESTING_conversion_Data_VecU8_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_Data_VecU8_identity,
      equality = java.util.Arrays::equals,
    )

  @Test
  fun bridgeVecString() =
    testConversion(
      listOf(listOf(), listOf("one"), listOf("one", "two"), listOf("one", "two", "three")).asSequence(),
      toString = { arr -> buildJsonArray { arr.forEach { add(it) } }.toString() },
      nativeToString = NativeTestingNice::TESTING_conversion_BridgeVecString_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_BridgeVecString_identity,
    )

  @Test
  fun bridgeVecMySimpleTestEnum() =
    testConversion(
      listOf(
        listOf(),
        listOf(MySimpleTestEnum.A),
        listOf(MySimpleTestEnum.B),
        listOf(
          MySimpleTestEnum.A,
          MySimpleTestEnum.B,
        ),
        listOf(MySimpleTestEnum.A, MySimpleTestEnum.A, MySimpleTestEnum.B),
        listOf(
          MySimpleTestEnum.B,
          MySimpleTestEnum.B,
        ),
      ).asSequence(),
      toString = { arr -> buildJsonArray { arr.forEach { add(it.toString()) } }.toString() },
      nativeToString = NativeTestingNice::TESTING_MySimpleTestEnum_BridgeVec_to_string,
      nativeIdentity = NativeTestingNice::TESTING_MySimpleTestEnum_BridgeVec_identity,
    )

  @Test
  fun mySimpleTestEnum() =
    testConversion(
      listOf(MySimpleTestEnum.A, MySimpleTestEnum.B).asSequence(),
      toString = {
        when (it) {
          is MySimpleTestEnum.A -> "A"
          is MySimpleTestEnum.B -> "B"
        }
      },
      nativeToString = NativeTestingNice::TESTING_MySimpleTestEnum_to_string,
      nativeIdentity = NativeTestingNice::TESTING_MySimpleTestEnum_identity,
    )

  @Test
  fun myTestPoint() =
    testConversion(
      listOf(MyTestPoint(1, 2)).asSequence(),
      toString = { p ->
        buildJsonArray {
          add(p._0)
          add(p._1)
        }.toString()
      },
      nativeToString = NativeTestingNice::TESTING_MyTestPoint_to_string,
      nativeIdentity = NativeTestingNice::TESTING_MyTestPoint_identity,
    )

  @Test
  fun myTestStruct() =
    testConversion(
      listOf(MyTestStruct(myStringField = "string", myNumericField = 12)).asSequence(),
      toString = { s ->
        buildJsonObject {
          put("myNumericField", s.myNumericField)
          put("myStringField", s.myStringField)
        }.toString()
      },
      nativeToString = NativeTestingNice::TESTING_MyTestStruct_to_string,
      nativeIdentity = NativeTestingNice::TESTING_MyTestStruct_identity,
    )

  @Test
  fun myTestEnum() =
    testConversion(
      listOf(
        MyTestEnum.Unit,
        MyTestEnum.Single(1),
        MyTestEnum.Double(2, 3),
        MyTestEnum.SingleNamed(4),
        MyTestEnum.Record(
          personName = "Nobody",
          personAge = 1001,
          position = MyTestPoint(5, 6),
          funStruct = MyTestStruct(7, "eight"),
        ),
      ).asSequence(),
      toString = { e ->
        when (e) {
          is MyTestEnum.Unit -> "\"unit\""
          is MyTestEnum.Single ->
            buildJsonObject {
              put("single", e._0)
            }
          is MyTestEnum.Double ->
            buildJsonObject {
              putJsonArray("double") {
                add(e._0)
                add(e._1)
              }
            }
          is MyTestEnum.SingleNamed ->
            buildJsonObject {
              putJsonObject("singleNamed") {
                put("x", e.x)
              }
            }
          is MyTestEnum.Record ->
            buildJsonObject {
              putJsonObject("record") {
                put("personName", e.personName)
                put("personAge", e.personAge)
                putJsonArray("position") {
                  add(e.position._0)
                  add(e.position._1)
                }
                putJsonObject("funStruct") {
                  put("myNumericField", e.funStruct.myNumericField)
                  put("myStringField", e.funStruct.myStringField)
                }
              }
            }
        }.toString()
      },
      nativeToString = NativeTestingNice::TESTING_MyTestEnum_to_string,
      nativeIdentity = NativeTestingNice::TESTING_MyTestEnum_identity,
    )

  @Test
  fun testAsync() {
    val tokio = TokioAsyncContext()
    for (count in listOf(0, 1, 2, 4, 8, 16, 32, 64, 128, 256)) {
      val data = NativeTestingNice.TESTING_TokioAsyncContext_FutureSuccessBytes(tokio, count).get()
      assertEquals(count, data.size)
    }
  }

  @Test
  fun testUuid() {
    testConversion(
      sequenceOf(UUID.randomUUID()),
      toString = Any::toString,
      nativeToString = NativeTestingNice::TESTING_conversion_Uuid_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_Uuid_identity,
    )
  }

  @Test
  fun testReturnedError() {
    val error = NativeTestingNice.TESTING_ReturnIoError()
    assertIs<java.io.IOException>(error)
    assertEquals(error.message, "testing")

    val error2 = NativeTestingNice.TESTING_ReturnSomeIoError(present = true)
    assertIs<java.io.IOException>(error2)
    assertEquals(error.message, "testing")

    val error3 = NativeTestingNice.TESTING_ReturnSomeIoError(present = false)
    assertEquals(error3, null)
  }

  @Test
  fun testDeviceId() {
    testConversion(
      IntRange(1, 127).asSequence(),
      toString = Any::toString,
      nativeToString = NativeTestingNice::TESTING_conversion_DeviceId_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_DeviceId_identity,
    )
  }

  @Test
  fun testTimestamp() {
    val fmt = DateTimeFormatterBuilder().appendInstant(3).toFormatter()

    fun instant2string(x: Instant): String = "${x.toEpochMilli()}ms ${fmt.format(x)}"
    testConversion(
      sequenceOf(
        Instant.ofEpochMilli(0),
        Instant.ofEpochMilli(1782938926226),
      ),
      toString = { instant2string(it) },
      nativeToString = NativeTestingNice::TESTING_conversion_Timestamp_to_string,
      nativeIdentity = NativeTestingNice::TESTING_conversion_Timestamp_identity,
    )
    // Our timestamps only store milliseconds, and don't preserve nanoseconds, so we _can't_
    // roundtrip via identity. Instead, we just validate the string format
    for (instant in listOf(
      Instant.ofEpochSecond(
        1782938926,
        226 * 100_000,
      ),
      Instant.ofEpochSecond(1782938, 738),
    )) {
      assertEquals(instant2string(instant), NativeTestingNice.TESTING_conversion_Timestamp_to_string(instant))
    }
  }
}
