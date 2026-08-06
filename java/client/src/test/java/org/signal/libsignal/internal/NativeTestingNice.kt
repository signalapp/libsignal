//
// Copyright (C) 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

@file:Suppress(
  "ktlint:standard:function-naming",
  "ktlint:standard:property-naming",
  "ktlint:standard:class-naming",
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

public sealed class CopyBackupMediaOut {
  public data class Item(
    public val _0: org.signal.libsignal.internal.BridgeCopyBackupMediaOutcome,
  ) : CopyBackupMediaOut()

  public data object InvalidDataInStream : CopyBackupMediaOut()

  public data object CredentialRejected : CopyBackupMediaOut()

  public data object CredentialRejectedWithoutAppropriateServerInfo : CopyBackupMediaOut()
}

public sealed class DeleteBackupMediaOut {
  public data class Item(
    public val _0: org.signal.libsignal.internal.BridgeDeleteBackupMediaItem,
  ) : DeleteBackupMediaOut()

  public data object InvalidDataInStream : DeleteBackupMediaOut()

  public data object CredentialRejected : DeleteBackupMediaOut()

  public data object CredentialRejectedWithoutAppropriateServerInfo : DeleteBackupMediaOut()
}

public sealed class GetCdnCredentialsOut {
  public data class Success(
    public val _0: org.signal.libsignal.net.BackupCdnCredentials,
  ) : GetCdnCredentialsOut()

  public data object CredentialRejected : GetCdnCredentialsOut()

  public data object MissingResponse : GetCdnCredentialsOut()
}

public data class GetDevicesOut(
  public val devices: List<org.signal.libsignal.internal.LinkedDeviceInternal>,
)

public sealed class GetMediaBackupInfoOut {
  public data class Success(
    public val _0: org.signal.libsignal.internal.BridgeMediaBackupInfo,
  ) : GetMediaBackupInfoOut()

  public data object CredentialRejected : GetMediaBackupInfoOut()

  public data object MissingResponse : GetMediaBackupInfoOut()
}

public sealed class GetMessageBackupInfoOut {
  public data class Success(
    public val _0: org.signal.libsignal.internal.BridgeMessageBackupInfo,
  ) : GetMessageBackupInfoOut()

  public data object CredentialRejected : GetMessageBackupInfoOut()

  public data object MissingResponse : GetMessageBackupInfoOut()
}

public sealed class GetSvrBCredentialsOut {
  public data class Success(
    public val username: String,
    public val password: String,
  ) : GetSvrBCredentialsOut()

  public data object CredentialRejected : GetSvrBCredentialsOut()

  public data object MissingResponse : GetSvrBCredentialsOut()
}

public data class ListMediaArgs(
  public val cursor: String?,
  public val limit: Int,
)

public sealed class ListMediaOut {
  public data class Page(
    public val _0: org.signal.libsignal.internal.ListMediaResponse,
  ) : ListMediaOut()

  public data object MalformedMediaId : ListMediaOut()

  public data object CredentialRejected : ListMediaOut()

  public data object MissingResponse : ListMediaOut()
}

public data class LookUpUsernameLinkArgs(
  public val uuid: java.util.UUID,
  public val entropy: ByteArray,
)

public sealed class LookUpUsernameLinkOut {
  public data class Success(
    public val _0: String,
  ) : LookUpUsernameLinkOut()

  public data object NotFound : LookUpUsernameLinkOut()

  public data object LinkDataTooShort : LookUpUsernameLinkOut()

  public data object MissingResponse : LookUpUsernameLinkOut()
}

public sealed class MySimpleTestEnum {
  public data object A : MySimpleTestEnum()

  public data object B : MySimpleTestEnum()
}

public sealed class MyTestEnum {
  public data object Unit : MyTestEnum()

  public data class Single(
    public val _0: Int,
  ) : MyTestEnum()

  public data class SingleNamed(
    public val x: Int,
  ) : MyTestEnum()

  public data class Double(
    public val _0: Int,
    public val _1: Int,
  ) : MyTestEnum()

  public data class Record(
    public val personName: String,
    public val personAge: Int,
    public val position: org.signal.libsignal.internal.MyTestPoint,
    public val funStruct: org.signal.libsignal.internal.MyTestStruct,
  ) : MyTestEnum()
}

public data class MyTestPoint(
  public val _0: Int,
  public val _1: Int,
)

public data class MyTestStruct(
  public val myNumericField: Int,
  public val myStringField: String,
)

public data class RemoveDeviceArgs(
  public val id: Int,
)

public sealed class RemoveDeviceOut {
  public data object Success : RemoveDeviceOut()
}

public data class ReserveUsernameHashArgs(
  public val usernames: List<ByteArray>,
)

public sealed class ReserveUsernameHashOut {
  public data class Success(
    public val _0: ByteArray,
  ) : ReserveUsernameHashOut()

  public data object UsernameNotAvailable : ReserveUsernameHashOut()
}

public data class SetDeviceNameArgs(
  public val id: Int,
  public val encryptedName: ByteArray,
)

public sealed class SetDeviceNameOut {
  public data object Success : SetDeviceNameOut()

  public data object DeviceNotFound : SetDeviceNameOut()
}

public data class SetUsernameLinkArgs(
  public val usernameCiphertext: ByteArray,
  public val keepLinkHandle: Boolean,
)

public sealed class SetUsernameLinkOut {
  public data class Success(
    public val _0: java.util.UUID,
  ) : SetUsernameLinkOut()

  public data object UsernameNotSet : SetUsernameLinkOut()
}

public sealed class SimpleBackupTestOut {
  public data object Success : SimpleBackupTestOut()

  public data object CredentialRejected : SimpleBackupTestOut()

  public data object MissingResponse : SimpleBackupTestOut()
}

public data class TestStreamChunk(
  public val chunk: List<String>,
  public val termination: Any?,
)

public object BridgeCopyBackupMediaItem_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    source_attachment_cdn: Any?,
    source_key: Any?,
    object_length: Any?,
    media_id: Any?,
    encryption_key: Any?,
  ): BridgeCopyBackupMediaItem =
    BridgeCopyBackupMediaItem(
      sourceAttachmentCdn =
        identity(source_attachment_cdn as Int),
      sourceKey =
        identity(source_key as String),
      objectLength =
        identity(object_length as Long),
      mediaId =
        identity(media_id as ByteArray),
      encryptionKey =
        identity(encryption_key as ByteArray),
    )
}

public object CopyBackupMediaOut_Item_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): CopyBackupMediaOut.Item =
    CopyBackupMediaOut.Item(
      _0 =
        downcastFromObject<org.signal.libsignal.internal.BridgeCopyBackupMediaOutcome>(_0 as Object),
    )
}

public object CopyBackupMediaOut_InvalidDataInStream_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): CopyBackupMediaOut.InvalidDataInStream = CopyBackupMediaOut.InvalidDataInStream
}

public object CopyBackupMediaOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): CopyBackupMediaOut.CredentialRejected = CopyBackupMediaOut.CredentialRejected
}

public object CopyBackupMediaOut_CredentialRejectedWithoutAppropriateServerInfo_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): CopyBackupMediaOut.CredentialRejectedWithoutAppropriateServerInfo =
    CopyBackupMediaOut.CredentialRejectedWithoutAppropriateServerInfo
}

public object DeleteBackupMediaOut_Item_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): DeleteBackupMediaOut.Item =
    DeleteBackupMediaOut.Item(
      _0 =
        downcastFromObject<org.signal.libsignal.internal.BridgeDeleteBackupMediaItem>(_0 as Object),
    )
}

public object DeleteBackupMediaOut_InvalidDataInStream_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): DeleteBackupMediaOut.InvalidDataInStream = DeleteBackupMediaOut.InvalidDataInStream
}

public object DeleteBackupMediaOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): DeleteBackupMediaOut.CredentialRejected = DeleteBackupMediaOut.CredentialRejected
}

public object DeleteBackupMediaOut_CredentialRejectedWithoutAppropriateServerInfo_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): DeleteBackupMediaOut.CredentialRejectedWithoutAppropriateServerInfo =
    DeleteBackupMediaOut.CredentialRejectedWithoutAppropriateServerInfo
}

public object GetCdnCredentialsOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): GetCdnCredentialsOut.Success =
    GetCdnCredentialsOut.Success(
      _0 =
        org.signal.libsignal.net.BackupCdnCredentials
          .fromFfiHeaders(_0 as Array<Object>),
    )
}

public object GetCdnCredentialsOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): GetCdnCredentialsOut.CredentialRejected = GetCdnCredentialsOut.CredentialRejected
}

public object GetCdnCredentialsOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): GetCdnCredentialsOut.MissingResponse = GetCdnCredentialsOut.MissingResponse
}

public object GetDevicesOut_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(devices: Any?): GetDevicesOut =
    GetDevicesOut(
      devices =
        mapBridgeVecReturn<Object, org.signal.libsignal.internal.LinkedDeviceInternal>({
          downcastFromObject<org.signal.libsignal.internal.LinkedDeviceInternal>(it)
        })(devices as Array<*>),
    )
}

public object GetMediaBackupInfoOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): GetMediaBackupInfoOut.Success =
    GetMediaBackupInfoOut.Success(
      _0 =
        downcastFromObject<org.signal.libsignal.internal.BridgeMediaBackupInfo>(_0 as Object),
    )
}

public object GetMediaBackupInfoOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): GetMediaBackupInfoOut.CredentialRejected = GetMediaBackupInfoOut.CredentialRejected
}

public object GetMediaBackupInfoOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): GetMediaBackupInfoOut.MissingResponse = GetMediaBackupInfoOut.MissingResponse
}

public object GetMessageBackupInfoOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): GetMessageBackupInfoOut.Success =
    GetMessageBackupInfoOut.Success(
      _0 =
        downcastFromObject<org.signal.libsignal.internal.BridgeMessageBackupInfo>(_0 as Object),
    )
}

public object GetMessageBackupInfoOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): GetMessageBackupInfoOut.CredentialRejected = GetMessageBackupInfoOut.CredentialRejected
}

public object GetMessageBackupInfoOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): GetMessageBackupInfoOut.MissingResponse = GetMessageBackupInfoOut.MissingResponse
}

public object GetSvrBCredentialsOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    username: Any?,
    password: Any?,
  ): GetSvrBCredentialsOut.Success =
    GetSvrBCredentialsOut.Success(
      username =
        identity(username as String),
      password =
        identity(password as String),
    )
}

public object GetSvrBCredentialsOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): GetSvrBCredentialsOut.CredentialRejected = GetSvrBCredentialsOut.CredentialRejected
}

public object GetSvrBCredentialsOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): GetSvrBCredentialsOut.MissingResponse = GetSvrBCredentialsOut.MissingResponse
}

public object ListMediaArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    cursor: Any?,
    limit: Any?,
  ): ListMediaArgs =
    ListMediaArgs(
      cursor =
        identity(cursor as String?),
      limit =
        identity(limit as Int),
    )
}

public object ListMediaOut_Page_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): ListMediaOut.Page =
    ListMediaOut.Page(
      _0 =
        downcastFromObject<org.signal.libsignal.internal.ListMediaResponse>(_0 as Object),
    )
}

public object ListMediaOut_MalformedMediaId_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): ListMediaOut.MalformedMediaId = ListMediaOut.MalformedMediaId
}

public object ListMediaOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): ListMediaOut.CredentialRejected = ListMediaOut.CredentialRejected
}

public object ListMediaOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): ListMediaOut.MissingResponse = ListMediaOut.MissingResponse
}

public object LookUpUsernameLinkArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    uuid: Any?,
    entropy: Any?,
  ): LookUpUsernameLinkArgs =
    LookUpUsernameLinkArgs(
      uuid =
        identity(uuid as java.util.UUID),
      entropy =
        identity(entropy as ByteArray),
    )
}

public object LookUpUsernameLinkOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): LookUpUsernameLinkOut.Success =
    LookUpUsernameLinkOut.Success(
      _0 =
        identity(_0 as String),
    )
}

public object LookUpUsernameLinkOut_NotFound_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): LookUpUsernameLinkOut.NotFound = LookUpUsernameLinkOut.NotFound
}

public object LookUpUsernameLinkOut_LinkDataTooShort_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): LookUpUsernameLinkOut.LinkDataTooShort = LookUpUsernameLinkOut.LinkDataTooShort
}

public object LookUpUsernameLinkOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): LookUpUsernameLinkOut.MissingResponse = LookUpUsernameLinkOut.MissingResponse
}

public object MySimpleTestEnum_A_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): MySimpleTestEnum.A = MySimpleTestEnum.A
}

public object MySimpleTestEnum_B_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): MySimpleTestEnum.B = MySimpleTestEnum.B
}

public object MyTestEnum_Unit_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): MyTestEnum.Unit = MyTestEnum.Unit
}

public object MyTestEnum_Single_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): MyTestEnum.Single =
    MyTestEnum.Single(
      _0 =
        identity(_0 as Int),
    )
}

public object MyTestEnum_SingleNamed_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(x: Any?): MyTestEnum.SingleNamed =
    MyTestEnum.SingleNamed(
      x =
        identity(x as Int),
    )
}

public object MyTestEnum_Double_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    _0: Any?,
    _1: Any?,
  ): MyTestEnum.Double =
    MyTestEnum.Double(
      _0 =
        identity(_0 as Int),
      _1 =
        identity(_1 as Int),
    )
}

public object MyTestEnum_Record_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    person_name: Any?,
    person_age: Any?,
    position: Any?,
    fun_struct: Any?,
  ): MyTestEnum.Record =
    MyTestEnum.Record(
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

public object MyTestPoint_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
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

public object MyTestStruct_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
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

public object RemoveDeviceArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(id: Any?): RemoveDeviceArgs =
    RemoveDeviceArgs(
      id =
        identity(id as Int),
    )
}

public object RemoveDeviceOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): RemoveDeviceOut.Success = RemoveDeviceOut.Success
}

public object ReserveUsernameHashArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(usernames: Any?): ReserveUsernameHashArgs =
    ReserveUsernameHashArgs(
      usernames =
        mapBridgeVecReturn<ByteArray, ByteArray>({ identity(it) })(usernames as Array<*>),
    )
}

public object ReserveUsernameHashOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): ReserveUsernameHashOut.Success =
    ReserveUsernameHashOut.Success(
      _0 =
        identity(_0 as ByteArray),
    )
}

public object ReserveUsernameHashOut_UsernameNotAvailable_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): ReserveUsernameHashOut.UsernameNotAvailable = ReserveUsernameHashOut.UsernameNotAvailable
}

public object SetDeviceNameArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
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

public object SetDeviceNameOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): SetDeviceNameOut.Success = SetDeviceNameOut.Success
}

public object SetDeviceNameOut_DeviceNotFound_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): SetDeviceNameOut.DeviceNotFound = SetDeviceNameOut.DeviceNotFound
}

public object SetUsernameLinkArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
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

public object SetUsernameLinkOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): SetUsernameLinkOut.Success =
    SetUsernameLinkOut.Success(
      _0 =
        identity(_0 as java.util.UUID),
    )
}

public object SetUsernameLinkOut_UsernameNotSet_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): SetUsernameLinkOut.UsernameNotSet = SetUsernameLinkOut.UsernameNotSet
}

public object SimpleBackupTestOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): SimpleBackupTestOut.Success = SimpleBackupTestOut.Success
}

public object SimpleBackupTestOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): SimpleBackupTestOut.CredentialRejected = SimpleBackupTestOut.CredentialRejected
}

public object SimpleBackupTestOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): SimpleBackupTestOut.MissingResponse = SimpleBackupTestOut.MissingResponse
}

public object TestStreamChunk_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
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

public sealed class MySimpleTestEnum_FfiArgType

@CalledFromNative
public object MySimpleTestEnum_A_FfiArgType : MySimpleTestEnum_FfiArgType()

public fun MySimpleTestEnum.A.toFfiArgType(): MySimpleTestEnum_A_FfiArgType = MySimpleTestEnum_A_FfiArgType

@CalledFromNative
public object MySimpleTestEnum_B_FfiArgType : MySimpleTestEnum_FfiArgType()

public fun MySimpleTestEnum.B.toFfiArgType(): MySimpleTestEnum_B_FfiArgType = MySimpleTestEnum_B_FfiArgType

public fun MySimpleTestEnum.toFfiArgTypeObject(): Object =
  convertToObject(
    when (this) {
      is MySimpleTestEnum.A -> this.toFfiArgType()
      is MySimpleTestEnum.B -> this.toFfiArgType()
    },
  )

public sealed class MyTestEnum_FfiArgType

@CalledFromNative
public object MyTestEnum_Unit_FfiArgType : MyTestEnum_FfiArgType()

public fun MyTestEnum.Unit.toFfiArgType(): MyTestEnum_Unit_FfiArgType = MyTestEnum_Unit_FfiArgType

@CalledFromNative
@Suppress("ktlint:standard:backing-property-naming")
public class MyTestEnum_Single_FfiArgType : MyTestEnum_FfiArgType {
  @CalledFromNative
  internal val _0: Int
  internal constructor(
    _0: Int,
  ) {
    this._0 = _0
  }
}

public fun MyTestEnum.Single.toFfiArgType(): MyTestEnum_Single_FfiArgType =
  MyTestEnum_Single_FfiArgType(
    _0 = identity(_0),
  )

@CalledFromNative
@Suppress("ktlint:standard:backing-property-naming")
public class MyTestEnum_SingleNamed_FfiArgType : MyTestEnum_FfiArgType {
  @CalledFromNative
  internal val x: Int
  internal constructor(
    x: Int,
  ) {
    this.x = x
  }
}

public fun MyTestEnum.SingleNamed.toFfiArgType(): MyTestEnum_SingleNamed_FfiArgType =
  MyTestEnum_SingleNamed_FfiArgType(
    x = identity(x),
  )

@CalledFromNative
@Suppress("ktlint:standard:backing-property-naming")
public class MyTestEnum_Double_FfiArgType : MyTestEnum_FfiArgType {
  @CalledFromNative
  internal val _0: Int

  @CalledFromNative
  internal val _1: Int
  internal constructor(
    _0: Int,
    _1: Int,
  ) {
    this._0 = _0
    this._1 = _1
  }
}

public fun MyTestEnum.Double.toFfiArgType(): MyTestEnum_Double_FfiArgType =
  MyTestEnum_Double_FfiArgType(
    _0 = identity(_0),
    _1 = identity(_1),
  )

@CalledFromNative
@Suppress("ktlint:standard:backing-property-naming")
public class MyTestEnum_Record_FfiArgType : MyTestEnum_FfiArgType {
  @CalledFromNative
  internal val person_name: Any?

  @CalledFromNative
  internal val person_age: Int

  @CalledFromNative
  internal val position: Any?

  @CalledFromNative
  internal val fun_struct: Any?
  internal constructor(
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

public fun MyTestEnum.Record.toFfiArgType(): MyTestEnum_Record_FfiArgType =
  MyTestEnum_Record_FfiArgType(
    person_name = identity(personName),
    person_age = identity(personAge),
    position = (org.signal.libsignal.internal.MyTestPoint::toFfiArgTypeObject)(position),
    fun_struct = (org.signal.libsignal.internal.MyTestStruct::toFfiArgTypeObject)(funStruct),
  )

public fun MyTestEnum.toFfiArgTypeObject(): Object =
  convertToObject(
    when (this) {
      is MyTestEnum.Unit -> this.toFfiArgType()
      is MyTestEnum.Single -> this.toFfiArgType()
      is MyTestEnum.SingleNamed -> this.toFfiArgType()
      is MyTestEnum.Double -> this.toFfiArgType()
      is MyTestEnum.Record -> this.toFfiArgType()
    },
  )

@CalledFromNative
@Suppress("ktlint:standard:backing-property-naming")
public class MyTestPoint_FfiArgType {
  @CalledFromNative
  internal val _0: Int

  @CalledFromNative
  internal val _1: Int
  internal constructor(
    _0: Int,
    _1: Int,
  ) {
    this._0 = _0
    this._1 = _1
  }
}

public fun MyTestPoint.toFfiArgType(): MyTestPoint_FfiArgType =
  MyTestPoint_FfiArgType(
    _0 = identity(_0),
    _1 = identity(_1),
  )

public fun MyTestPoint.toFfiArgTypeObject(): Object = convertToObject(this.toFfiArgType())

@CalledFromNative
@Suppress("ktlint:standard:backing-property-naming")
public class MyTestStruct_FfiArgType {
  @CalledFromNative
  internal val my_numeric_field: Int

  @CalledFromNative
  internal val my_string_field: Any?
  internal constructor(
    my_numeric_field: Int,
    my_string_field: Any?,
  ) {
    this.my_numeric_field = my_numeric_field
    this.my_string_field = my_string_field
  }
}

public fun MyTestStruct.toFfiArgType(): MyTestStruct_FfiArgType =
  MyTestStruct_FfiArgType(
    my_numeric_field = identity(myNumericField),
    my_string_field = identity(myStringField),
  )

public fun MyTestStruct.toFfiArgTypeObject(): Object = convertToObject(this.toFfiArgType())

public object NativeTestingNice {
  public fun TESTING_BackupDeleteAllTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, org.signal.libsignal.internal.SimpleBackupTestOut>> {
    val ffiOut =
      NativeTesting.TESTING_BackupDeleteAllTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Void?, Object, Void?, org.signal.libsignal.internal.SimpleBackupTestOut>({
        identity(it)
      }, { downcastFromObject<org.signal.libsignal.internal.SimpleBackupTestOut>(it) })(ffiOut)
  }

  public fun TESTING_BackupListMediaTests(): List<org.signal.libsignal.net.GrpcTestCase<org.signal.libsignal.internal.ListMediaArgs, org.signal.libsignal.internal.ListMediaOut>> {
    val ffiOut =
      NativeTesting.TESTING_BackupListMediaTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Object, Object, org.signal.libsignal.internal.ListMediaArgs, org.signal.libsignal.internal.ListMediaOut>({
        downcastFromObject<org.signal.libsignal.internal.ListMediaArgs>(it)
      }, { downcastFromObject<org.signal.libsignal.internal.ListMediaOut>(it) })(ffiOut)
  }

  public fun TESTING_BackupRefreshTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, org.signal.libsignal.internal.SimpleBackupTestOut>> {
    val ffiOut =
      NativeTesting.TESTING_BackupRefreshTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Void?, Object, Void?, org.signal.libsignal.internal.SimpleBackupTestOut>({
        identity(it)
      }, { downcastFromObject<org.signal.libsignal.internal.SimpleBackupTestOut>(it) })(ffiOut)
  }

  public fun TESTING_BackupSetPublicKeyTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, org.signal.libsignal.internal.SimpleBackupTestOut>> {
    val ffiOut =
      NativeTesting.TESTING_BackupSetPublicKeyTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Void?, Object, Void?, org.signal.libsignal.internal.SimpleBackupTestOut>({
        identity(it)
      }, { downcastFromObject<org.signal.libsignal.internal.SimpleBackupTestOut>(it) })(ffiOut)
  }

  public fun TESTING_ClearPushTokenTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, Void?>> {
    val ffiOut =
      NativeTesting.TESTING_ClearPushTokenTests()

    return org.signal.libsignal.net.GrpcTestCase.resultConverter<Void?, Void?, Void?, Void?>({
      identity(it)
    }, { identity(it) })(ffiOut)
  }

  public fun TESTING_ClearRegistrationLockTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, Void?>> {
    val ffiOut =
      NativeTesting.TESTING_ClearRegistrationLockTests()

    return org.signal.libsignal.net.GrpcTestCase.resultConverter<Void?, Void?, Void?, Void?>({
      identity(it)
    }, { identity(it) })(ffiOut)
  }

  public fun TESTING_CopyBackupMediaTests(): List<org.signal.libsignal.net.GrpcTestCase<List<org.signal.libsignal.internal.BridgeCopyBackupMediaItem>, List<org.signal.libsignal.internal.CopyBackupMediaOut>>> {
    val ffiOut =
      NativeTesting.TESTING_CopyBackupMediaTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Array<*>, Array<*>, List<org.signal.libsignal.internal.BridgeCopyBackupMediaItem>, List<org.signal.libsignal.internal.CopyBackupMediaOut>>({
        mapBridgeVecReturn<Object, org.signal.libsignal.internal.BridgeCopyBackupMediaItem>({
          downcastFromObject<org.signal.libsignal.internal.BridgeCopyBackupMediaItem>(it)
        })(it)
      }, {
        mapBridgeVecReturn<Object, org.signal.libsignal.internal.CopyBackupMediaOut>({
          downcastFromObject<org.signal.libsignal.internal.CopyBackupMediaOut>(it)
        })(it)
      })(ffiOut)
  }

  public fun TESTING_DeleteBackupMediaTests(): List<org.signal.libsignal.net.GrpcTestCase<List<org.signal.libsignal.internal.BridgeDeleteBackupMediaItem>, List<org.signal.libsignal.internal.DeleteBackupMediaOut>>> {
    val ffiOut =
      NativeTesting.TESTING_DeleteBackupMediaTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Array<*>, Array<*>, List<org.signal.libsignal.internal.BridgeDeleteBackupMediaItem>, List<org.signal.libsignal.internal.DeleteBackupMediaOut>>({
        mapBridgeVecReturn<Object, org.signal.libsignal.internal.BridgeDeleteBackupMediaItem>({
          downcastFromObject<org.signal.libsignal.internal.BridgeDeleteBackupMediaItem>(it)
        })(it)
      }, {
        mapBridgeVecReturn<Object, org.signal.libsignal.internal.DeleteBackupMediaOut>({
          downcastFromObject<org.signal.libsignal.internal.DeleteBackupMediaOut>(it)
        })(it)
      })(ffiOut)
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

  public fun TESTING_GetBackupCdnCredentialsTests(): List<org.signal.libsignal.net.GrpcTestCase<Int, org.signal.libsignal.internal.GetCdnCredentialsOut>> {
    val ffiOut =
      NativeTesting.TESTING_GetBackupCdnCredentialsTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Int, Object, Int, org.signal.libsignal.internal.GetCdnCredentialsOut>({
        identity(it)
      }, { downcastFromObject<org.signal.libsignal.internal.GetCdnCredentialsOut>(it) })(ffiOut)
  }

  public fun TESTING_GetBackupSvrBCredentialsTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, org.signal.libsignal.internal.GetSvrBCredentialsOut>> {
    val ffiOut =
      NativeTesting.TESTING_GetBackupSvrBCredentialsTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Void?, Object, Void?, org.signal.libsignal.internal.GetSvrBCredentialsOut>({
        identity(it)
      }, { downcastFromObject<org.signal.libsignal.internal.GetSvrBCredentialsOut>(it) })(ffiOut)
  }

  public fun TESTING_GetDevicesTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, org.signal.libsignal.internal.GetDevicesOut>> {
    val ffiOut =
      NativeTesting.TESTING_GetDevicesTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Void?, Object, Void?, org.signal.libsignal.internal.GetDevicesOut>({
        identity(it)
      }, { downcastFromObject<org.signal.libsignal.internal.GetDevicesOut>(it) })(ffiOut)
  }

  public fun TESTING_GetMediaBackupInfoTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, org.signal.libsignal.internal.GetMediaBackupInfoOut>> {
    val ffiOut =
      NativeTesting.TESTING_GetMediaBackupInfoTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Void?, Object, Void?, org.signal.libsignal.internal.GetMediaBackupInfoOut>({
        identity(it)
      }, { downcastFromObject<org.signal.libsignal.internal.GetMediaBackupInfoOut>(it) })(ffiOut)
  }

  public fun TESTING_GetMessageBackupInfoTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, org.signal.libsignal.internal.GetMessageBackupInfoOut>> {
    val ffiOut =
      NativeTesting.TESTING_GetMessageBackupInfoTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Void?, Object, Void?, org.signal.libsignal.internal.GetMessageBackupInfoOut>({
        identity(it)
      }, { downcastFromObject<org.signal.libsignal.internal.GetMessageBackupInfoOut>(it) })(ffiOut)
  }

  public fun TESTING_LookUpUsernameLinkTests(): List<org.signal.libsignal.net.GrpcTestCase<org.signal.libsignal.internal.LookUpUsernameLinkArgs, org.signal.libsignal.internal.LookUpUsernameLinkOut>> {
    val ffiOut =
      NativeTesting.TESTING_LookUpUsernameLinkTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Object, Object, org.signal.libsignal.internal.LookUpUsernameLinkArgs, org.signal.libsignal.internal.LookUpUsernameLinkOut>({
        downcastFromObject<org.signal.libsignal.internal.LookUpUsernameLinkArgs>(it)
      }, { downcastFromObject<org.signal.libsignal.internal.LookUpUsernameLinkOut>(it) })(ffiOut)
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

  public fun TESTING_SetDiscoverableByPhoneNumberTests(): List<org.signal.libsignal.net.GrpcTestCase<Boolean, Void?>> {
    val ffiOut =
      NativeTesting.TESTING_SetDiscoverableByPhoneNumberTests()

    return org.signal.libsignal.net.GrpcTestCase.resultConverter<Boolean, Void?, Boolean, Void?>({
      identity(it)
    }, { identity(it) })(ffiOut)
  }

  public fun TESTING_SetPushTokenFcmTests(): List<org.signal.libsignal.net.GrpcTestCase<String, Void?>> {
    val ffiOut =
      NativeTesting.TESTING_SetPushTokenFcmTests()

    return org.signal.libsignal.net.GrpcTestCase.resultConverter<String, Void?, String, Void?>({
      identity(it)
    }, { identity(it) })(ffiOut)
  }

  public fun TESTING_SetRegistrationLockTests(): List<org.signal.libsignal.net.GrpcTestCase<ByteArray, Void?>> {
    val ffiOut =
      NativeTesting.TESTING_SetRegistrationLockTests()

    return org.signal.libsignal.net.GrpcTestCase.resultConverter<ByteArray, Void?, ByteArray, Void?>({
      identity(it)
    }, { identity(it) })(ffiOut)
  }

  public fun TESTING_SetRegistrationRecoveryPasswordTests(): List<org.signal.libsignal.net.GrpcTestCase<ByteArray, Void?>> {
    val ffiOut =
      NativeTesting.TESTING_SetRegistrationRecoveryPasswordTests()

    return org.signal.libsignal.net.GrpcTestCase.resultConverter<ByteArray, Void?, ByteArray, Void?>({
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
