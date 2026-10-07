//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal

// Public for testing
public object NativeNiceHelpers {
  @JvmStatic
  @Suppress("NOTHING_TO_INLINE")
  public inline fun <T> identity(x: T): T = x

  @JvmStatic
  @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN", "NOTHING_TO_INLINE")
  public inline fun convertToObject(x: Any): Object = x as Object

  @JvmStatic
  public inline fun <InA, InB, OutA, OutB> mapPair(
    crossinline transformA: (InA) -> OutA,
    crossinline transformB: (InB) -> OutB,
  ): (Pair<InA, InB>) -> Pair<OutA, OutB> = { Pair(transformA(it.first), transformB(it.second)) }

  @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
  public inline fun <reified T> downcastFromObject(obj: Object): T = obj as T

  public inline fun <Ffi, Nice> mapBridgeVecArg(crossinline thunk: (Nice) -> Ffi): (List<Nice>) -> Array<*> =
    { input ->
      val inputIter = input.iterator()
      Array<Any?>(input.size) {
        thunk(inputIter.next())
      }
    }

  public inline fun <reified Ffi, Nice> mapBridgeVecReturn(crossinline thunk: (Ffi) -> Nice): (Array<*>) -> List<Nice> =
    { arr ->
      arr.asSequence().map { thunk(it as Ffi) }.toList()
    }

  @JvmStatic
  public inline fun <FfiA, FfiB, NiceA, NiceB> argPairConverter(
    crossinline transformA: (NiceA) -> FfiA,
    crossinline transformB: (NiceB) -> FfiB,
  ): (Pair<NiceA, NiceB>) -> Array<Any?> = { arrayOf(transformA(it.first), transformB(it.second)) }

  public inline fun <FfiValue, NiceValue> stringMapArgConverter(
    crossinline transformValue: (NiceValue) -> FfiValue,
  ): (Map<String, NiceValue>) -> Array<*> =
    { map ->
      val out = Array<Any?>(map.size * 2, { null })
      for (entry in map.iterator().withIndex()) {
        out[entry.index * 2] = entry.value.key
        out[entry.index * 2 + 1] = transformValue(entry.value.value)
      }
      out
    }

  public inline fun <reified FfiValue, NiceValue> stringMapReturnConverter(
    crossinline transformValue: (FfiValue) -> NiceValue,
  ): (Array<*>) -> Map<String, NiceValue> =
    { arr ->
      require(arr.size % 2 == 0)
      buildMap(arr.size / 2) {
        val iter = arr.iterator()
        while (iter.hasNext()) {
          val k = iter.next() as String
          val v = iter.next() as FfiValue
          put(k, transformValue(v))
        }
      }
    }
}
