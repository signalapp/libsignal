//
// Copyright (C) 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

@file:Suppress(
  "ktlint:standard:function-naming",
  "ktlint:standard:property-naming",
  "ktlint:standard:filename",
)

package org.signal.libsignal.internal

internal object NativeTestingNice {
  @Suppress("NOTHING_TO_INLINE")
  private inline fun <T> identity(x: T): T = x

  @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
  private fun convertToObject(x: Any): Object = x as Object

  private inline fun <InA, InB, OutA, OutB> mapPair(
    crossinline transformA: (InA) -> OutA,
    crossinline transformB: (InB) -> OutB,
  ): (Pair<InA, InB>) -> Pair<OutA, OutB> =
    {
      Pair(transformA(it.first), transformB(it.second))
    }

  public fun TESTING_TestingIntBox_Get(myIntBox: org.signal.libsignal.internal.TestingIntBox): Int {
    val ffi_my_int_box = identity(myIntBox)
    val ffiOut =
      NativeTesting.TESTING_TestingIntBox_Get(
        ffi_my_int_box,
      )

    return identity(ffiOut)
  }

  public fun TESTING_TokioAsyncContext_FutureSuccessBytes(
    asyncCtx: TokioAsyncContext,
    count: Int,
  ): CompletableFuture<ByteArray> {
    val ffi_count = identity(count)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        NativeTesting.TESTING_TokioAsyncContext_FutureSuccessBytes(
          asyncCtxHandle.nativeHandle(),
          ffi_count,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply { identity(it) }
  }

  public fun TESTING_conversion_Data_identity(x: ByteArray): ByteArray {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_Data_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_Data_to_string(x: ByteArray): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_Data_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_ServiceId_identity(
    x: org.signal.libsignal.protocol.ServiceId,
  ): org.signal.libsignal.protocol.ServiceId {
    val ffi_x = (org.signal.libsignal.protocol.ServiceId::toServiceIdFixedWidthBinary)(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_ServiceId_identity(
        ffi_x,
      )

    return org.signal.libsignal.protocol.ServiceId
      .parseFromFixedWidthBinary(ffiOut)
  }

  public fun TESTING_conversion_ServiceId_to_string(x: org.signal.libsignal.protocol.ServiceId): String {
    val ffi_x = (org.signal.libsignal.protocol.ServiceId::toServiceIdFixedWidthBinary)(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_ServiceId_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_bool_identity(x: Boolean): Boolean {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_bool_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_bool_to_string(x: Boolean): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_bool_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_i32_identity(x: Int): Int {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_i32_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_i32_to_string(x: Int): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_i32_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_string_identity(x: String): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_string_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_u16_identity(x: Int): Int {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_u16_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_u16_to_string(x: Int): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_u16_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_u8_identity(x: Int): Int {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_u8_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_u8_to_string(x: Int): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_u8_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }
}
