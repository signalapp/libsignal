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
  @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
  public fun convertToObject(x: Any): Object = x as Object

  @JvmStatic
  public inline fun <InA, InB, OutA, OutB> mapPair(
    crossinline transformA: (InA) -> OutA,
    crossinline transformB: (InB) -> OutB,
  ): (Pair<InA, InB>) -> Pair<OutA, OutB> = { Pair(transformA(it.first), transformB(it.second)) }

  @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
  public inline fun <reified T> downcastFromObject(obj: Object): T = obj as T
}
