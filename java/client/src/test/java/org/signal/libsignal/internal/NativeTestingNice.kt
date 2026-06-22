//
// Copyright (C) 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

@file:Suppress(
  "ktlint:standard:function-naming",
  "ktlint:standard:property-naming",
  "ktlint:standard:filename",
  "ktlint:standard:max-line-length",
)

package org.signal.libsignal.internal

import org.signal.libsignal.internal.NativeNiceHelpers.convertToObject
import org.signal.libsignal.internal.NativeNiceHelpers.downcastFromObject
import org.signal.libsignal.internal.NativeNiceHelpers.identity

internal sealed class MySimpleTestEnum {
  internal data object A : MySimpleTestEnum() {
    @JvmStatic
    @CalledFromNative
    fun fromNative(): A = A

    @CalledFromNative
    internal object FfiArgType : MySimpleTestEnum.FfiArgType()

    override fun toFfiArgType(): FfiArgType = FfiArgType
  }

  internal data object B : MySimpleTestEnum() {
    @JvmStatic
    @CalledFromNative
    fun fromNative(): B = B

    @CalledFromNative
    internal object FfiArgType : MySimpleTestEnum.FfiArgType()

    override fun toFfiArgType(): FfiArgType = FfiArgType
  }

  internal sealed class FfiArgType

  internal abstract fun toFfiArgType(): FfiArgType
}

internal fun MySimpleTestEnum.toFfiArgTypeObject(): Object = convertToObject(this.toFfiArgType())

internal sealed class MyTestEnum {
  internal data object Unit : MyTestEnum() {
    @JvmStatic
    @CalledFromNative
    fun fromNative(): Unit = Unit

    @CalledFromNative
    internal object FfiArgType : MyTestEnum.FfiArgType()

    override fun toFfiArgType(): FfiArgType = FfiArgType
  }

  internal data class Single(
    val _0: Int,
  ) : MyTestEnum() {
    companion object {
      @JvmStatic
      @CalledFromNative
      fun fromNative(_0: Any?): Single =
        Single(
          _0 =
            identity(_0 as Int),
        )
    }

    @CalledFromNative
    @Suppress("ktlint:standard:backing-property-naming")
    internal class FfiArgType : MyTestEnum.FfiArgType {
      @CalledFromNative
      internal val _0: Int
      constructor(
        _0: Int,
      ) {
        this._0 = _0
      }
    }

    override fun toFfiArgType(): FfiArgType =
      FfiArgType(
        _0 = identity(_0),
      )
  }

  internal data class SingleNamed(
    val x: Int,
  ) : MyTestEnum() {
    companion object {
      @JvmStatic
      @CalledFromNative
      fun fromNative(x: Any?): SingleNamed =
        SingleNamed(
          x =
            identity(x as Int),
        )
    }

    @CalledFromNative
    @Suppress("ktlint:standard:backing-property-naming")
    internal class FfiArgType : MyTestEnum.FfiArgType {
      @CalledFromNative
      internal val x: Int
      constructor(
        x: Int,
      ) {
        this.x = x
      }
    }

    override fun toFfiArgType(): FfiArgType =
      FfiArgType(
        x = identity(x),
      )
  }

  internal data class Double(
    val _0: Int,
    val _1: Int,
  ) : MyTestEnum() {
    companion object {
      @JvmStatic
      @CalledFromNative
      fun fromNative(
        _0: Any?,
        _1: Any?,
      ): Double =
        Double(
          _0 =
            identity(_0 as Int),
          _1 =
            identity(_1 as Int),
        )
    }

    @CalledFromNative
    @Suppress("ktlint:standard:backing-property-naming")
    internal class FfiArgType : MyTestEnum.FfiArgType {
      @CalledFromNative
      internal val _0: Int

      @CalledFromNative
      internal val _1: Int
      constructor(
        _0: Int,
        _1: Int,
      ) {
        this._0 = _0
        this._1 = _1
      }
    }

    override fun toFfiArgType(): FfiArgType =
      FfiArgType(
        _0 = identity(_0),
        _1 = identity(_1),
      )
  }

  internal data class Record(
    val personName: String,
    val personAge: Int,
    val position: org.signal.libsignal.internal.MyTestPoint,
    val funStruct: org.signal.libsignal.internal.MyTestStruct,
  ) : MyTestEnum() {
    companion object {
      @JvmStatic
      @CalledFromNative
      fun fromNative(
        person_name: Any?,
        person_age: Any?,
        position: Any?,
        fun_struct: Any?,
      ): Record =
        Record(
          personName =
            identity(person_name as String),
          personAge =
            identity(person_age as Int),
          position =
            downcastFromObject<org.signal.libsignal.internal.MyTestPoint>(position as Object),
          funStruct =
            downcastFromObject<org.signal.libsignal.internal.MyTestStruct>(fun_struct as Object),
        )
    }

    @CalledFromNative
    @Suppress("ktlint:standard:backing-property-naming")
    internal class FfiArgType : MyTestEnum.FfiArgType {
      @CalledFromNative
      internal val person_name: Any?

      @CalledFromNative
      internal val person_age: Int

      @CalledFromNative
      internal val position: Any?

      @CalledFromNative
      internal val fun_struct: Any?
      constructor(
        person_name: Any?,
        person_age: Int,
        position: Any?,
        fun_struct: Any?,
      ) {
        this.person_name = person_name
        this.person_age = person_age
        this.position = position
        this.fun_struct = fun_struct
      }
    }

    override fun toFfiArgType(): FfiArgType =
      FfiArgType(
        person_name = identity(personName),
        person_age = identity(personAge),
        position = (org.signal.libsignal.internal.MyTestPoint::toFfiArgTypeObject)(position),
        fun_struct = (org.signal.libsignal.internal.MyTestStruct::toFfiArgTypeObject)(funStruct),
      )
  }

  internal sealed class FfiArgType

  internal abstract fun toFfiArgType(): FfiArgType
}

internal fun MyTestEnum.toFfiArgTypeObject(): Object = convertToObject(this.toFfiArgType())

internal data class MyTestPoint(
  val _0: Int,
  val _1: Int,
) {
  companion object {
    @JvmStatic
    @CalledFromNative
    fun fromNative(
      _0: Any?,
      _1: Any?,
    ): MyTestPoint =
      MyTestPoint(
        _0 =
          identity(_0 as Int),
        _1 =
          identity(_1 as Int),
      )
  }

  @CalledFromNative
  @Suppress("ktlint:standard:backing-property-naming")
  internal class FfiArgType {
    @CalledFromNative
    internal val _0: Int

    @CalledFromNative
    internal val _1: Int
    constructor(
      _0: Int,
      _1: Int,
    ) {
      this._0 = _0
      this._1 = _1
    }
  }

  fun toFfiArgType(): FfiArgType =
    FfiArgType(
      _0 = identity(_0),
      _1 = identity(_1),
    )
}

internal fun MyTestPoint.toFfiArgTypeObject(): Object = convertToObject(this.toFfiArgType())

internal data class MyTestStruct(
  val myNumericField: Int,
  val myStringField: String,
) {
  companion object {
    @JvmStatic
    @CalledFromNative
    fun fromNative(
      my_numeric_field: Any?,
      my_string_field: Any?,
    ): MyTestStruct =
      MyTestStruct(
        myNumericField =
          identity(my_numeric_field as Int),
        myStringField =
          identity(my_string_field as String),
      )
  }

  @CalledFromNative
  @Suppress("ktlint:standard:backing-property-naming")
  internal class FfiArgType {
    @CalledFromNative
    internal val my_numeric_field: Int

    @CalledFromNative
    internal val my_string_field: Any?
    constructor(
      my_numeric_field: Int,
      my_string_field: Any?,
    ) {
      this.my_numeric_field = my_numeric_field
      this.my_string_field = my_string_field
    }
  }

  fun toFfiArgType(): FfiArgType =
    FfiArgType(
      my_numeric_field = identity(myNumericField),
      my_string_field = identity(myStringField),
    )
}

internal fun MyTestStruct.toFfiArgTypeObject(): Object = convertToObject(this.toFfiArgType())

internal data class SetDeviceNameArgs(
  val id: Int,
  val encryptedName: ByteArray,
) {
  companion object {
    @JvmStatic
    @CalledFromNative
    fun fromNative(
      id: Any?,
      encrypted_name: Any?,
    ): SetDeviceNameArgs =
      SetDeviceNameArgs(
        id =
          identity(id as Int),
        encryptedName =
          identity(encrypted_name as ByteArray),
      )
  }
}

internal sealed class SetDeviceNameOut {
  internal data object Success : SetDeviceNameOut() {
    @JvmStatic
    @CalledFromNative
    fun fromNative(): Success = Success
  }

  internal data object DeviceNotFound : SetDeviceNameOut() {
    @JvmStatic
    @CalledFromNative
    fun fromNative(): DeviceNotFound = DeviceNotFound
  }
}

internal object NativeTestingNice {
  public fun TESTING_MySimpleTestEnum_identity(
    x: org.signal.libsignal.internal.MySimpleTestEnum,
  ): org.signal.libsignal.internal.MySimpleTestEnum {
    val ffi_x = (org.signal.libsignal.internal.MySimpleTestEnum::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MySimpleTestEnum_identity(
        ffi_x,
      )

    return downcastFromObject<org.signal.libsignal.internal.MySimpleTestEnum>(ffiOut)
  }

  public fun TESTING_MySimpleTestEnum_to_string(x: org.signal.libsignal.internal.MySimpleTestEnum): String {
    val ffi_x = (org.signal.libsignal.internal.MySimpleTestEnum::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MySimpleTestEnum_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_MyTestEnum_identity(
    x: org.signal.libsignal.internal.MyTestEnum,
  ): org.signal.libsignal.internal.MyTestEnum {
    val ffi_x = (org.signal.libsignal.internal.MyTestEnum::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MyTestEnum_identity(
        ffi_x,
      )

    return downcastFromObject<org.signal.libsignal.internal.MyTestEnum>(ffiOut)
  }

  public fun TESTING_MyTestEnum_to_string(x: org.signal.libsignal.internal.MyTestEnum): String {
    val ffi_x = (org.signal.libsignal.internal.MyTestEnum::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MyTestEnum_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_MyTestPoint_identity(
    x: org.signal.libsignal.internal.MyTestPoint,
  ): org.signal.libsignal.internal.MyTestPoint {
    val ffi_x = (org.signal.libsignal.internal.MyTestPoint::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MyTestPoint_identity(
        ffi_x,
      )

    return downcastFromObject<org.signal.libsignal.internal.MyTestPoint>(ffiOut)
  }

  public fun TESTING_MyTestPoint_to_string(x: org.signal.libsignal.internal.MyTestPoint): String {
    val ffi_x = (org.signal.libsignal.internal.MyTestPoint::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MyTestPoint_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_MyTestStruct_identity(
    x: org.signal.libsignal.internal.MyTestStruct,
  ): org.signal.libsignal.internal.MyTestStruct {
    val ffi_x = (org.signal.libsignal.internal.MyTestStruct::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MyTestStruct_identity(
        ffi_x,
      )

    return downcastFromObject<org.signal.libsignal.internal.MyTestStruct>(ffiOut)
  }

  public fun TESTING_MyTestStruct_to_string(x: org.signal.libsignal.internal.MyTestStruct): String {
    val ffi_x = (org.signal.libsignal.internal.MyTestStruct::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MyTestStruct_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_SetDeviceNameTests(): List<org.signal.libsignal.net.GrpcTestCase<org.signal.libsignal.internal.SetDeviceNameArgs, org.signal.libsignal.internal.SetDeviceNameOut>> {
    val ffiOut =
      NativeTesting.TESTING_SetDeviceNameTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Object, Object, org.signal.libsignal.internal.SetDeviceNameArgs, org.signal.libsignal.internal.SetDeviceNameOut>({
        downcastFromObject<org.signal.libsignal.internal.SetDeviceNameArgs>(it)
      }, { downcastFromObject<org.signal.libsignal.internal.SetDeviceNameOut>(it) })(ffiOut)
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
  }

  public fun TESTING_conversion_Data_VecU8_identity(x: ByteArray): ByteArray {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_Data_VecU8_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_Data_VecU8_to_string(x: ByteArray): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_Data_VecU8_to_string(
        ffi_x,
      )

    return identity(ffiOut)
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
