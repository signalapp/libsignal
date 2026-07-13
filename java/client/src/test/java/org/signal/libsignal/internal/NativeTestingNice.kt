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
  "PLATFORM_CLASS_MAPPED_TO_KOTLIN",
)

package org.signal.libsignal.internal

import org.signal.libsignal.internal.NativeNiceHelpers.convertToObject
import org.signal.libsignal.internal.NativeNiceHelpers.downcastFromObject
import org.signal.libsignal.internal.NativeNiceHelpers.identity
import org.signal.libsignal.internal.NativeNiceHelpers.mapBridgeVecArg
import org.signal.libsignal.internal.NativeNiceHelpers.mapBridgeVecReturn

public data class GetDevicesOut(
  val devices: List<org.signal.libsignal.internal.LinkedDeviceInternal>,
) {
  public companion object {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(devices: Any?): GetDevicesOut =
      GetDevicesOut(
        devices =
          mapBridgeVecReturn<Object, org.signal.libsignal.internal.LinkedDeviceInternal>({
            downcastFromObject<org.signal.libsignal.internal.LinkedDeviceInternal>(it)
          })(devices as Array<*>),
      )
  }
}

public sealed class MySimpleTestEnum {
  public data object A : MySimpleTestEnum() {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(): A = A

    @CalledFromNative
    internal object FfiArgType : MySimpleTestEnum.FfiArgType()

    override fun toFfiArgType(): FfiArgType = FfiArgType
  }

  public data object B : MySimpleTestEnum() {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(): B = B

    @CalledFromNative
    internal object FfiArgType : MySimpleTestEnum.FfiArgType()

    override fun toFfiArgType(): FfiArgType = FfiArgType
  }

  public sealed class FfiArgType

  internal abstract fun toFfiArgType(): FfiArgType
}

internal fun MySimpleTestEnum.toFfiArgTypeObject(): Object = convertToObject(this.toFfiArgType())

public sealed class MyTestEnum {
  public data object Unit : MyTestEnum() {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(): Unit = Unit

    @CalledFromNative
    internal object FfiArgType : MyTestEnum.FfiArgType()

    override fun toFfiArgType(): FfiArgType = FfiArgType
  }

  public data class Single(
    val _0: Int,
  ) : MyTestEnum() {
    public companion object {
      @JvmStatic
      @JvmName("fromNative")
      @CalledFromNative
      internal fun fromNative(_0: Any?): Single =
        Single(
          _0 =
            identity(_0 as Int),
        )
    }

    @CalledFromNative
    @Suppress("ktlint:standard:backing-property-naming")
    public class FfiArgType : MyTestEnum.FfiArgType {
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

  public data class SingleNamed(
    val x: Int,
  ) : MyTestEnum() {
    public companion object {
      @JvmStatic
      @JvmName("fromNative")
      @CalledFromNative
      internal fun fromNative(x: Any?): SingleNamed =
        SingleNamed(
          x =
            identity(x as Int),
        )
    }

    @CalledFromNative
    @Suppress("ktlint:standard:backing-property-naming")
    public class FfiArgType : MyTestEnum.FfiArgType {
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

  public data class Double(
    val _0: Int,
    val _1: Int,
  ) : MyTestEnum() {
    public companion object {
      @JvmStatic
      @JvmName("fromNative")
      @CalledFromNative
      internal fun fromNative(
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
    public class FfiArgType : MyTestEnum.FfiArgType {
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

  public data class Record(
    val personName: String,
    val personAge: Int,
    val position: org.signal.libsignal.internal.MyTestPoint,
    val funStruct: org.signal.libsignal.internal.MyTestStruct,
  ) : MyTestEnum() {
    public companion object {
      @JvmStatic
      @JvmName("fromNative")
      @CalledFromNative
      internal fun fromNative(
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
    public class FfiArgType : MyTestEnum.FfiArgType {
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

  public sealed class FfiArgType

  internal abstract fun toFfiArgType(): FfiArgType
}

internal fun MyTestEnum.toFfiArgTypeObject(): Object = convertToObject(this.toFfiArgType())

public data class MyTestPoint(
  val _0: Int,
  val _1: Int,
) {
  public companion object {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(
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
  public class FfiArgType {
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

public data class MyTestStruct(
  val myNumericField: Int,
  val myStringField: String,
) {
  public companion object {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(
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
  public class FfiArgType {
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

public data class RemoveDeviceArgs(
  val id: Int,
) {
  public companion object {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(id: Any?): RemoveDeviceArgs =
      RemoveDeviceArgs(
        id =
          identity(id as Int),
      )
  }
}

public sealed class RemoveDeviceOut {
  public data object Success : RemoveDeviceOut() {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(): Success = Success
  }
}

public data class ReserveUsernameHashArgs(
  val usernames: List<ByteArray>,
) {
  public companion object {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(usernames: Any?): ReserveUsernameHashArgs =
      ReserveUsernameHashArgs(
        usernames =
          mapBridgeVecReturn<ByteArray, ByteArray>({ identity(it) })(usernames as Array<*>),
      )
  }
}

public sealed class ReserveUsernameHashOut {
  public data class Success(
    val _0: ByteArray,
  ) : ReserveUsernameHashOut() {
    public companion object {
      @JvmStatic
      @JvmName("fromNative")
      @CalledFromNative
      internal fun fromNative(_0: Any?): Success =
        Success(
          _0 =
            identity(_0 as ByteArray),
        )
    }
  }

  public data object UsernameNotAvailable : ReserveUsernameHashOut() {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(): UsernameNotAvailable = UsernameNotAvailable
  }
}

public data class SetDeviceNameArgs(
  val id: Int,
  val encryptedName: ByteArray,
) {
  public companion object {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(
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

public sealed class SetDeviceNameOut {
  public data object Success : SetDeviceNameOut() {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(): Success = Success
  }

  public data object DeviceNotFound : SetDeviceNameOut() {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(): DeviceNotFound = DeviceNotFound
  }
}

public data class SetUsernameLinkArgs(
  val usernameCiphertext: ByteArray,
  val keepLinkHandle: Boolean,
) {
  public companion object {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(
      username_ciphertext: Any?,
      keep_link_handle: Any?,
    ): SetUsernameLinkArgs =
      SetUsernameLinkArgs(
        usernameCiphertext =
          identity(username_ciphertext as ByteArray),
        keepLinkHandle =
          identity(keep_link_handle as Boolean),
      )
  }
}

public sealed class SetUsernameLinkOut {
  public data class Success(
    val _0: java.util.UUID,
  ) : SetUsernameLinkOut() {
    public companion object {
      @JvmStatic
      @JvmName("fromNative")
      @CalledFromNative
      internal fun fromNative(_0: Any?): Success =
        Success(
          _0 =
            identity(_0 as java.util.UUID),
        )
    }
  }

  public data object UsernameNotSet : SetUsernameLinkOut() {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(): UsernameNotSet = UsernameNotSet
  }
}

public data class TestStreamChunk(
  val chunk: List<String>,
  val termination: Any?,
) {
  public companion object {
    @JvmStatic
    @JvmName("fromNative")
    @CalledFromNative
    internal fun fromNative(
      chunk: Any?,
      termination: Any?,
    ): TestStreamChunk =
      TestStreamChunk(
        chunk =
          mapBridgeVecReturn<String, String>({ identity(it) })(chunk as Array<*>),
        termination =
          identity(termination as Object?),
      )
  }
}

public object NativeTestingNice {
  public fun TESTING_ClearPushTokenTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, Void?>> {
    val ffiOut =
      NativeTesting.TESTING_ClearPushTokenTests()

    return org.signal.libsignal.net.GrpcTestCase.resultConverter<Void?, Void?, Void?, Void?>({
      identity(it)
    }, { identity(it) })(ffiOut)
  }

  public fun TESTING_DeleteUsernameHashTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, Void?>> {
    val ffiOut =
      NativeTesting.TESTING_DeleteUsernameHashTests()

    return org.signal.libsignal.net.GrpcTestCase.resultConverter<Void?, Void?, Void?, Void?>({
      identity(it)
    }, { identity(it) })(ffiOut)
  }

  public fun TESTING_DeleteUsernameLinkTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, Void?>> {
    val ffiOut =
      NativeTesting.TESTING_DeleteUsernameLinkTests()

    return org.signal.libsignal.net.GrpcTestCase.resultConverter<Void?, Void?, Void?, Void?>({
      identity(it)
    }, { identity(it) })(ffiOut)
  }

  public fun TESTING_GetDevicesTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, org.signal.libsignal.internal.GetDevicesOut>> {
    val ffiOut =
      NativeTesting.TESTING_GetDevicesTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Void?, Object, Void?, org.signal.libsignal.internal.GetDevicesOut>({
        identity(it)
      }, { downcastFromObject<org.signal.libsignal.internal.GetDevicesOut>(it) })(ffiOut)
  }

  public fun TESTING_MySimpleTestEnum_BridgeVec_identity(
    x: List<org.signal.libsignal.internal.MySimpleTestEnum>,
  ): List<org.signal.libsignal.internal.MySimpleTestEnum> {
    val ffi_x =
      mapBridgeVecArg<Object, org.signal.libsignal.internal.MySimpleTestEnum>({
        (org.signal.libsignal.internal.MySimpleTestEnum::toFfiArgTypeObject)(it)
      })(x)
    val ffiOut =
      NativeTesting.TESTING_MySimpleTestEnum_BridgeVec_identity(
        ffi_x,
      )

    return mapBridgeVecReturn<Object, org.signal.libsignal.internal.MySimpleTestEnum>({
      downcastFromObject<org.signal.libsignal.internal.MySimpleTestEnum>(it)
    })(ffiOut)
  }

  public fun TESTING_MySimpleTestEnum_BridgeVec_to_string(
    x: List<org.signal.libsignal.internal.MySimpleTestEnum>,
  ): String {
    val ffi_x =
      mapBridgeVecArg<Object, org.signal.libsignal.internal.MySimpleTestEnum>({
        (org.signal.libsignal.internal.MySimpleTestEnum::toFfiArgTypeObject)(it)
      })(x)
    val ffiOut =
      NativeTesting.TESTING_MySimpleTestEnum_BridgeVec_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

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

  public fun TESTING_RemoveDeviceTests(): List<org.signal.libsignal.net.GrpcTestCase<org.signal.libsignal.internal.RemoveDeviceArgs, org.signal.libsignal.internal.RemoveDeviceOut>> {
    val ffiOut =
      NativeTesting.TESTING_RemoveDeviceTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Object, Object, org.signal.libsignal.internal.RemoveDeviceArgs, org.signal.libsignal.internal.RemoveDeviceOut>({
        downcastFromObject<org.signal.libsignal.internal.RemoveDeviceArgs>(it)
      }, { downcastFromObject<org.signal.libsignal.internal.RemoveDeviceOut>(it) })(ffiOut)
  }

  public fun TESTING_ReserveUsernameHashTests(): List<org.signal.libsignal.net.GrpcTestCase<org.signal.libsignal.internal.ReserveUsernameHashArgs, org.signal.libsignal.internal.ReserveUsernameHashOut>> {
    val ffiOut =
      NativeTesting.TESTING_ReserveUsernameHashTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Object, Object, org.signal.libsignal.internal.ReserveUsernameHashArgs, org.signal.libsignal.internal.ReserveUsernameHashOut>({
        downcastFromObject<org.signal.libsignal.internal.ReserveUsernameHashArgs>(it)
      }, { downcastFromObject<org.signal.libsignal.internal.ReserveUsernameHashOut>(it) })(ffiOut)
  }

  public fun TESTING_ReturnIoError(): Throwable {
    val ffiOut =
      NativeTesting.TESTING_ReturnIoError()

    return identity(ffiOut)
  }

  public fun TESTING_ReturnSomeIoError(present: Boolean): Throwable? {
    val ffi_present = identity(present)
    val ffiOut =
      NativeTesting.TESTING_ReturnSomeIoError(
        ffi_present,
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

  public fun TESTING_SetPushTokenFcmTests(): List<org.signal.libsignal.net.GrpcTestCase<String, Void?>> {
    val ffiOut =
      NativeTesting.TESTING_SetPushTokenFcmTests()

    return org.signal.libsignal.net.GrpcTestCase.resultConverter<String, Void?, String, Void?>({
      identity(it)
    }, { identity(it) })(ffiOut)
  }

  public fun TESTING_SetUsernameLinkTests(): List<org.signal.libsignal.net.GrpcTestCase<org.signal.libsignal.internal.SetUsernameLinkArgs, org.signal.libsignal.internal.SetUsernameLinkOut>> {
    val ffiOut =
      NativeTesting.TESTING_SetUsernameLinkTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Object, Object, org.signal.libsignal.internal.SetUsernameLinkArgs, org.signal.libsignal.internal.SetUsernameLinkOut>({
        downcastFromObject<org.signal.libsignal.internal.SetUsernameLinkArgs>(it)
      }, { downcastFromObject<org.signal.libsignal.internal.SetUsernameLinkOut>(it) })(ffiOut)
  }

  public fun TESTING_TestStreamChunk_return(): org.signal.libsignal.internal.TestStreamChunk {
    val ffiOut =
      NativeTesting.TESTING_TestStreamChunk_return()

    return downcastFromObject<org.signal.libsignal.internal.TestStreamChunk>(ffiOut)
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

  public fun TESTING_conversion_BridgeVecData32_identity(x: List<ByteArray>): List<ByteArray> {
    val ffi_x = mapBridgeVecArg<ByteArray, ByteArray>({ identity(it) })(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_BridgeVecData32_identity(
        ffi_x,
      )

    return mapBridgeVecReturn<ByteArray, ByteArray>({ identity(it) })(ffiOut)
  }

  public fun TESTING_conversion_BridgeVecData32_to_string(x: List<ByteArray>): String {
    val ffi_x = mapBridgeVecArg<ByteArray, ByteArray>({ identity(it) })(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_BridgeVecData32_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_BridgeVecString_identity(x: List<String>): List<String> {
    val ffi_x = mapBridgeVecArg<String, String>({ identity(it) })(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_BridgeVecString_identity(
        ffi_x,
      )

    return mapBridgeVecReturn<String, String>({ identity(it) })(ffiOut)
  }

  public fun TESTING_conversion_BridgeVecString_to_string(x: List<String>): String {
    val ffi_x = mapBridgeVecArg<String, String>({ identity(it) })(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_BridgeVecString_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_Data32_identity(x: ByteArray): ByteArray {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_Data32_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_Data32_to_string(x: ByteArray): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_Data32_to_string(
        ffi_x,
      )

    return identity(ffiOut)
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

  public fun TESTING_conversion_DeviceId_identity(
    x: org.signal.libsignal.protocol.DeviceId,
  ): org.signal.libsignal.protocol.DeviceId {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_DeviceId_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_DeviceId_to_string(x: org.signal.libsignal.protocol.DeviceId): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_DeviceId_to_string(
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

  public fun TESTING_conversion_Timestamp_identity(x: java.time.Instant): java.time.Instant {
    val ffi_x = (java.time.Instant::toEpochMilli)(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_Timestamp_identity(
        ffi_x,
      )

    return (java.time.Instant::ofEpochMilli)(ffiOut)
  }

  public fun TESTING_conversion_Timestamp_to_string(x: java.time.Instant): String {
    val ffi_x = (java.time.Instant::toEpochMilli)(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_Timestamp_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_Uuid_identity(x: java.util.UUID): java.util.UUID {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_Uuid_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_Uuid_to_string(x: java.util.UUID): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_Uuid_to_string(
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
