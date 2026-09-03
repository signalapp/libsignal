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
  "ktlint:standard:no-consecutive-comments",
  "PLATFORM_CLASS_MAPPED_TO_KOTLIN",
)

package org.signal.libsignal.internal

import org.signal.libsignal.internal.NativeNiceHelpers.convertToObject
import org.signal.libsignal.internal.NativeNiceHelpers.downcastFromObject
import org.signal.libsignal.internal.NativeNiceHelpers.identity
import org.signal.libsignal.internal.NativeNiceHelpers.mapBridgeVecArg
import org.signal.libsignal.internal.NativeNiceHelpers.mapBridgeVecReturn
import org.signal.libsignal.internal.NativeNiceHelpers.mapPair

public data class CheckSvrCredentialsArgs(
  public val number: String,
  public val passwords: List<String>,
)

public data class ConfirmUsernameArgs(
  public val username: String,
  public val usernameCiphertext: ByteArray,
)

public sealed class ConfirmUsernameOut {
  public data class Success(
    public val _0: java.util.UUID,
  ) : ConfirmUsernameOut()

  public data object ReservationNotFound : ConfirmUsernameOut()

  public data object UsernameNotAvailable : ConfirmUsernameOut()
}

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
    public val _0: org.signal.libsignal.net.DeleteBackupMediaItem,
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
  public val devices: List<org.signal.libsignal.net.LinkedDevice>,
)

public sealed class GetMediaBackupInfoOut {
  public data class Success(
    public val _0: org.signal.libsignal.net.MediaBackupInfo,
  ) : GetMediaBackupInfoOut()

  public data object CredentialRejected : GetMediaBackupInfoOut()

  public data object MissingResponse : GetMediaBackupInfoOut()
}

public sealed class GetMessageBackupInfoOut {
  public data class Success(
    public val _0: org.signal.libsignal.net.MessageBackupInfo,
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
    public val _0: org.signal.libsignal.net.ListBackupMediaResponse,
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

/*
// org.signal.libsignal.internal.MyNiceTypeEnum

public sealed class MyNiceTypeEnumNot {
  public data object Unit : MyNiceTypeEnumNot()

  public data class Single(
    public val _0: Int,
  ) : MyNiceTypeEnumNot()
}

*/

/*
// org.signal.libsignal.internal.MyNiceTypeSimpleEnum

public sealed class MyNiceTypeSimpleEnumNot {
  public data object A : MyNiceTypeSimpleEnumNot()

  public data object B : MyNiceTypeSimpleEnumNot()
}

*/

/*
// org.signal.libsignal.internal.MyNiceTypeStruct

public data class MyNiceTypeStructNot(
  public val x: Int,
  public val y: Int,
)

*/

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

public sealed class RedeemBackupReceiptOut {
  public data object Success : RedeemBackupReceiptOut()

  public data object InvalidReceipt : RedeemBackupReceiptOut()

  public data object MissingBackupId : RedeemBackupReceiptOut()

  public data object MissingResponse : RedeemBackupReceiptOut()
}

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
  ): Any? =
    org.signal.libsignal.net.CopyBackupMediaItem(
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

public object CallQualitySurveyInternal_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    user_satisfied: Any?,
    call_quality_issues: Any?,
    additional_issues_description: Any?,
    debug_log_url: Any?,
    start_timestamp: Any?,
    end_timestamp: Any?,
    call_type: Any?,
    success: Any?,
    call_end_reason: Any?,
    connection_rtt_median: Any?,
    audio_rtt_median: Any?,
    video_rtt_median: Any?,
    audio_recv_jitter_median: Any?,
    video_recv_jitter_median: Any?,
    audio_send_jitter_median: Any?,
    video_send_jitter_median: Any?,
    audio_recv_packet_loss_fraction: Any?,
    video_recv_packet_loss_fraction: Any?,
    audio_send_packet_loss_fraction: Any?,
    video_send_packet_loss_fraction: Any?,
    call_telemetry: Any?,
    call_id_hash: Any?,
  ): Any? =
    org.signal.libsignal.net.CallQualitySurvey(
      userSatisfied =
        identity(user_satisfied as Boolean),
      callQualityIssues =
        mapBridgeVecReturn<String, String>({ identity(it) })(call_quality_issues as Array<*>),
      additionalIssuesDescription =
        identity(additional_issues_description as String?),
      debugLogUrl =
        identity(debug_log_url as String?),
      startTimestamp =
        (java.time.Instant::ofEpochMilli)(start_timestamp as Long),
      endTimestamp =
        (java.time.Instant::ofEpochMilli)(end_timestamp as Long),
      callType =
        identity(call_type as String),
      success =
        identity(success as Boolean),
      callEndReason =
        identity(call_end_reason as String),
      connectionRttMedian =
        identity(connection_rtt_median as Float?),
      audioRttMedian =
        identity(audio_rtt_median as Float?),
      videoRttMedian =
        identity(video_rtt_median as Float?),
      audioRecvJitterMedian =
        identity(audio_recv_jitter_median as Float?),
      videoRecvJitterMedian =
        identity(video_recv_jitter_median as Float?),
      audioSendJitterMedian =
        identity(audio_send_jitter_median as Float?),
      videoSendJitterMedian =
        identity(video_send_jitter_median as Float?),
      audioRecvPacketLossFraction =
        identity(audio_recv_packet_loss_fraction as Float?),
      videoRecvPacketLossFraction =
        identity(video_recv_packet_loss_fraction as Float?),
      audioSendPacketLossFraction =
        identity(audio_send_packet_loss_fraction as Float?),
      videoSendPacketLossFraction =
        identity(video_send_packet_loss_fraction as Float?),
      callTelemetry =
        identity(call_telemetry as ByteArray?),
      callIdHash =
        identity(call_id_hash as ByteArray?),
    )
}

public object CheckSvrCredentialsArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    number: Any?,
    passwords: Any?,
  ): Any? =
    CheckSvrCredentialsArgs(
      number =
        identity(number as String),
      passwords =
        mapBridgeVecReturn<String, String>({ identity(it) })(passwords as Array<*>),
    )
}

public object ConfirmUsernameArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    username: Any?,
    username_ciphertext: Any?,
  ): Any? =
    ConfirmUsernameArgs(
      username =
        identity(username as String),
      usernameCiphertext =
        identity(username_ciphertext as ByteArray),
    )
}

public object ConfirmUsernameOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): Any? =
    ConfirmUsernameOut.Success(
      _0 =
        identity(_0 as java.util.UUID),
    )
}

public object ConfirmUsernameOut_ReservationNotFound_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = ConfirmUsernameOut.ReservationNotFound
}

public object ConfirmUsernameOut_UsernameNotAvailable_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = ConfirmUsernameOut.UsernameNotAvailable
}

public object CopyBackupMediaOut_Item_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): Any? =
    CopyBackupMediaOut.Item(
      _0 =
        downcastFromObject<org.signal.libsignal.internal.BridgeCopyBackupMediaOutcome>(_0 as Object),
    )
}

public object CopyBackupMediaOut_InvalidDataInStream_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = CopyBackupMediaOut.InvalidDataInStream
}

public object CopyBackupMediaOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = CopyBackupMediaOut.CredentialRejected
}

public object CopyBackupMediaOut_CredentialRejectedWithoutAppropriateServerInfo_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = CopyBackupMediaOut.CredentialRejectedWithoutAppropriateServerInfo
}

public object DeleteBackupMediaOut_Item_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): Any? =
    DeleteBackupMediaOut.Item(
      _0 =
        downcastFromObject<org.signal.libsignal.net.DeleteBackupMediaItem>(_0 as Object),
    )
}

public object DeleteBackupMediaOut_InvalidDataInStream_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = DeleteBackupMediaOut.InvalidDataInStream
}

public object DeleteBackupMediaOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = DeleteBackupMediaOut.CredentialRejected
}

public object DeleteBackupMediaOut_CredentialRejectedWithoutAppropriateServerInfo_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = DeleteBackupMediaOut.CredentialRejectedWithoutAppropriateServerInfo
}

public object GetCdnCredentialsOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): Any? =
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
  internal fun fromNative(): Any? = GetCdnCredentialsOut.CredentialRejected
}

public object GetCdnCredentialsOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = GetCdnCredentialsOut.MissingResponse
}

public object GetDevicesOut_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(devices: Any?): Any? =
    GetDevicesOut(
      devices =
        mapBridgeVecReturn<Object, org.signal.libsignal.net.LinkedDevice>({
          downcastFromObject<org.signal.libsignal.net.LinkedDevice>(it)
        })(devices as Array<*>),
    )
}

public object GetMediaBackupInfoOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): Any? =
    GetMediaBackupInfoOut.Success(
      _0 =
        downcastFromObject<org.signal.libsignal.net.MediaBackupInfo>(_0 as Object),
    )
}

public object GetMediaBackupInfoOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = GetMediaBackupInfoOut.CredentialRejected
}

public object GetMediaBackupInfoOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = GetMediaBackupInfoOut.MissingResponse
}

public object GetMessageBackupInfoOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): Any? =
    GetMessageBackupInfoOut.Success(
      _0 =
        downcastFromObject<org.signal.libsignal.net.MessageBackupInfo>(_0 as Object),
    )
}

public object GetMessageBackupInfoOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = GetMessageBackupInfoOut.CredentialRejected
}

public object GetMessageBackupInfoOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = GetMessageBackupInfoOut.MissingResponse
}

public object GetSvrBCredentialsOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    username: Any?,
    password: Any?,
  ): Any? =
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
  internal fun fromNative(): Any? = GetSvrBCredentialsOut.CredentialRejected
}

public object GetSvrBCredentialsOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = GetSvrBCredentialsOut.MissingResponse
}

public object ListMediaArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    cursor: Any?,
    limit: Any?,
  ): Any? =
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
  internal fun fromNative(_0: Any?): Any? =
    ListMediaOut.Page(
      _0 =
        downcastFromObject<org.signal.libsignal.net.ListBackupMediaResponse>(_0 as Object),
    )
}

public object ListMediaOut_MalformedMediaId_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = ListMediaOut.MalformedMediaId
}

public object ListMediaOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = ListMediaOut.CredentialRejected
}

public object ListMediaOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = ListMediaOut.MissingResponse
}

public object LookUpUsernameLinkArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    uuid: Any?,
    entropy: Any?,
  ): Any? =
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
  internal fun fromNative(_0: Any?): Any? =
    LookUpUsernameLinkOut.Success(
      _0 =
        identity(_0 as String),
    )
}

public object LookUpUsernameLinkOut_NotFound_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = LookUpUsernameLinkOut.NotFound
}

public object LookUpUsernameLinkOut_LinkDataTooShort_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = LookUpUsernameLinkOut.LinkDataTooShort
}

public object LookUpUsernameLinkOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = LookUpUsernameLinkOut.MissingResponse
}

public object MyNiceTypeEnumNot_Unit_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = org.signal.libsignal.internal.MyNiceTypeEnum.Unit
}

public object MyNiceTypeEnumNot_Single_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): Any? =
    org.signal.libsignal.internal.MyNiceTypeEnum.Single(
      _0 =
        identity(_0 as Int),
    )
}

public object MyNiceTypeSimpleEnumNot_A_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = org.signal.libsignal.internal.MyNiceTypeSimpleEnum.A
}

public object MyNiceTypeSimpleEnumNot_B_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = org.signal.libsignal.internal.MyNiceTypeSimpleEnum.B
}

public object MyNiceTypeStructNot_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    x: Any?,
    y: Any?,
  ): Any? =
    org.signal.libsignal.internal.MyNiceTypeStruct(
      x =
        identity(x as Int),
      y =
        identity(y as Int),
    )
}

public object MySimpleTestEnum_A_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = MySimpleTestEnum.A
}

public object MySimpleTestEnum_B_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = MySimpleTestEnum.B
}

public object MyTestEnum_Unit_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = MyTestEnum.Unit
}

public object MyTestEnum_Single_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): Any? =
    MyTestEnum.Single(
      _0 =
        identity(_0 as Int),
    )
}

public object MyTestEnum_SingleNamed_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(x: Any?): Any? =
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
  ): Any? =
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
  ): Any? =
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
  ): Any? =
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
  ): Any? =
    MyTestStruct(
      myNumericField =
        identity(my_numeric_field as Int),
      myStringField =
        identity(my_string_field as String),
    )
}

public object RedeemBackupReceiptOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = RedeemBackupReceiptOut.Success
}

public object RedeemBackupReceiptOut_InvalidReceipt_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = RedeemBackupReceiptOut.InvalidReceipt
}

public object RedeemBackupReceiptOut_MissingBackupId_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = RedeemBackupReceiptOut.MissingBackupId
}

public object RedeemBackupReceiptOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = RedeemBackupReceiptOut.MissingResponse
}

public object RemoveDeviceArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(id: Any?): Any? =
    RemoveDeviceArgs(
      id =
        identity(id as Int),
    )
}

public object RemoveDeviceOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = RemoveDeviceOut.Success
}

public object ReserveUsernameHashArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(usernames: Any?): Any? =
    ReserveUsernameHashArgs(
      usernames =
        mapBridgeVecReturn<ByteArray, ByteArray>({ identity(it) })(usernames as Array<*>),
    )
}

public object ReserveUsernameHashOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(_0: Any?): Any? =
    ReserveUsernameHashOut.Success(
      _0 =
        identity(_0 as ByteArray),
    )
}

public object ReserveUsernameHashOut_UsernameNotAvailable_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = ReserveUsernameHashOut.UsernameNotAvailable
}

public object SetDeviceNameArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    id: Any?,
    encrypted_name: Any?,
  ): Any? =
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
  internal fun fromNative(): Any? = SetDeviceNameOut.Success
}

public object SetDeviceNameOut_DeviceNotFound_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = SetDeviceNameOut.DeviceNotFound
}

public object SetUsernameLinkArgs_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    username_ciphertext: Any?,
    keep_link_handle: Any?,
  ): Any? =
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
  internal fun fromNative(_0: Any?): Any? =
    SetUsernameLinkOut.Success(
      _0 =
        identity(_0 as java.util.UUID),
    )
}

public object SetUsernameLinkOut_UsernameNotSet_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = SetUsernameLinkOut.UsernameNotSet
}

public object SimpleBackupTestOut_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = SimpleBackupTestOut.Success
}

public object SimpleBackupTestOut_CredentialRejected_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = SimpleBackupTestOut.CredentialRejected
}

public object SimpleBackupTestOut_MissingResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = SimpleBackupTestOut.MissingResponse
}

public object TestStreamChunk_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    chunk: Any?,
    termination: Any?,
  ): Any? =
    TestStreamChunk(
      chunk =
        mapBridgeVecReturn<String, String>({ identity(it) })(chunk as Array<*>),
      termination =
        identity(termination as Object?),
    )
}

public sealed class MyNiceTypeEnumNot_FfiArgType

@CalledFromNative
public object MyNiceTypeEnumNot_Unit_FfiArgType : MyNiceTypeEnumNot_FfiArgType()

public fun org.signal.libsignal.internal.MyNiceTypeEnum.Unit.toFfiArgType(): MyNiceTypeEnumNot_Unit_FfiArgType =
  MyNiceTypeEnumNot_Unit_FfiArgType

@CalledFromNative
@Suppress("ktlint:standard:backing-property-naming")
public class MyNiceTypeEnumNot_Single_FfiArgType : MyNiceTypeEnumNot_FfiArgType {
  @CalledFromNative
  internal val _0: Int
  internal constructor(
    _0: Int,
  ) {
    this._0 = _0
  }
}

public fun org.signal.libsignal.internal.MyNiceTypeEnum.Single.toFfiArgType(): MyNiceTypeEnumNot_Single_FfiArgType =
  MyNiceTypeEnumNot_Single_FfiArgType(
    _0 = identity(_0),
  )

public fun org.signal.libsignal.internal.MyNiceTypeEnum.toFfiArgTypeObject(): Object =
  convertToObject(
    when (this) {
      is org.signal.libsignal.internal.MyNiceTypeEnum.Unit -> this.toFfiArgType()
      is org.signal.libsignal.internal.MyNiceTypeEnum.Single -> this.toFfiArgType()
    },
  )

public sealed class MyNiceTypeSimpleEnumNot_FfiArgType

@CalledFromNative
public object MyNiceTypeSimpleEnumNot_A_FfiArgType : MyNiceTypeSimpleEnumNot_FfiArgType()

public fun org.signal.libsignal.internal.MyNiceTypeSimpleEnum.A.toFfiArgType(): MyNiceTypeSimpleEnumNot_A_FfiArgType =
  MyNiceTypeSimpleEnumNot_A_FfiArgType

@CalledFromNative
public object MyNiceTypeSimpleEnumNot_B_FfiArgType : MyNiceTypeSimpleEnumNot_FfiArgType()

public fun org.signal.libsignal.internal.MyNiceTypeSimpleEnum.B.toFfiArgType(): MyNiceTypeSimpleEnumNot_B_FfiArgType =
  MyNiceTypeSimpleEnumNot_B_FfiArgType

public fun org.signal.libsignal.internal.MyNiceTypeSimpleEnum.toFfiArgTypeObject(): Object =
  convertToObject(
    when (this) {
      is org.signal.libsignal.internal.MyNiceTypeSimpleEnum.A -> this.toFfiArgType()
      is org.signal.libsignal.internal.MyNiceTypeSimpleEnum.B -> this.toFfiArgType()
    },
  )

@CalledFromNative
@Suppress("ktlint:standard:backing-property-naming")
public class MyNiceTypeStructNot_FfiArgType {
  @CalledFromNative
  internal val x: Int

  @CalledFromNative
  internal val y: Int
  internal constructor(
    x: Int,
    y: Int,
  ) {
    this.x = x
    this.y = y
  }
}

public fun org.signal.libsignal.internal.MyNiceTypeStruct.toFfiArgType(): MyNiceTypeStructNot_FfiArgType =
  MyNiceTypeStructNot_FfiArgType(
    x = identity(x),
    y = identity(y),
  )

public fun org.signal.libsignal.internal.MyNiceTypeStruct.toFfiArgTypeObject(): Object =
  convertToObject(this.toFfiArgType())

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

  public fun TESTING_CheckSvrCredentialsTests(): List<org.signal.libsignal.net.GrpcTestCase<org.signal.libsignal.internal.CheckSvrCredentialsArgs, List<Pair<String, org.signal.libsignal.net.AuthCheckResult>>>> {
    val ffiOut =
      NativeTesting.TESTING_CheckSvrCredentialsTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Object, Array<*>, org.signal.libsignal.internal.CheckSvrCredentialsArgs, List<Pair<String, org.signal.libsignal.net.AuthCheckResult>>>({
        downcastFromObject<org.signal.libsignal.internal.CheckSvrCredentialsArgs>(it)
      }, {
        mapBridgeVecReturn<Pair<String, Object>, Pair<String, org.signal.libsignal.net.AuthCheckResult>>({
          mapPair<String, Object, String, org.signal.libsignal.net.AuthCheckResult>({
            identity(it)
          }, { downcastFromObject<org.signal.libsignal.net.AuthCheckResult>(it) })(it)
        })(it)
      })(ffiOut)
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

  public fun TESTING_ConfirmUsernameTests(): List<org.signal.libsignal.net.GrpcTestCase<org.signal.libsignal.internal.ConfirmUsernameArgs, org.signal.libsignal.internal.ConfirmUsernameOut>> {
    val ffiOut =
      NativeTesting.TESTING_ConfirmUsernameTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Object, Object, org.signal.libsignal.internal.ConfirmUsernameArgs, org.signal.libsignal.internal.ConfirmUsernameOut>({
        downcastFromObject<org.signal.libsignal.internal.ConfirmUsernameArgs>(it)
      }, { downcastFromObject<org.signal.libsignal.internal.ConfirmUsernameOut>(it) })(ffiOut)
  }

  public fun TESTING_CopyBackupMediaTests(): List<org.signal.libsignal.net.GrpcTestCase<List<org.signal.libsignal.net.CopyBackupMediaItem>, List<org.signal.libsignal.internal.CopyBackupMediaOut>>> {
    val ffiOut =
      NativeTesting.TESTING_CopyBackupMediaTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Array<*>, Array<*>, List<org.signal.libsignal.net.CopyBackupMediaItem>, List<org.signal.libsignal.internal.CopyBackupMediaOut>>({
        mapBridgeVecReturn<Object, org.signal.libsignal.net.CopyBackupMediaItem>({
          downcastFromObject<org.signal.libsignal.net.CopyBackupMediaItem>(it)
        })(it)
      }, {
        mapBridgeVecReturn<Object, org.signal.libsignal.internal.CopyBackupMediaOut>({
          downcastFromObject<org.signal.libsignal.internal.CopyBackupMediaOut>(it)
        })(it)
      })(ffiOut)
  }

  public fun TESTING_DeleteAccountTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, Void?>> {
    val ffiOut =
      NativeTesting.TESTING_DeleteAccountTests()

    return org.signal.libsignal.net.GrpcTestCase.resultConverter<Void?, Void?, Void?, Void?>({
      identity(it)
    }, { identity(it) })(ffiOut)
  }

  public fun TESTING_DeleteBackupMediaTests(): List<org.signal.libsignal.net.GrpcTestCase<List<org.signal.libsignal.net.DeleteBackupMediaItem>, List<org.signal.libsignal.internal.DeleteBackupMediaOut>>> {
    val ffiOut =
      NativeTesting.TESTING_DeleteBackupMediaTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Array<*>, Array<*>, List<org.signal.libsignal.net.DeleteBackupMediaItem>, List<org.signal.libsignal.internal.DeleteBackupMediaOut>>({
        mapBridgeVecReturn<Object, org.signal.libsignal.net.DeleteBackupMediaItem>({
          downcastFromObject<org.signal.libsignal.net.DeleteBackupMediaItem>(it)
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

  public fun TESTING_GetCurrencyConversionsTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, org.signal.libsignal.internal.CurrencyConversionsInternal>> {
    val ffiOut =
      NativeTesting.TESTING_GetCurrencyConversionsTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Void?, Object, Void?, org.signal.libsignal.internal.CurrencyConversionsInternal>({
        identity(it)
      }, { downcastFromObject<org.signal.libsignal.internal.CurrencyConversionsInternal>(it) })(ffiOut)
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

  public fun TESTING_GetPreKeyCountTests(): List<org.signal.libsignal.net.GrpcTestCase<Void?, org.signal.libsignal.net.PreKeyCounts>> {
    val ffiOut =
      NativeTesting.TESTING_GetPreKeyCountTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Void?, Object, Void?, org.signal.libsignal.net.PreKeyCounts>({
        identity(it)
      }, { downcastFromObject<org.signal.libsignal.net.PreKeyCounts>(it) })(ffiOut)
  }

  public fun TESTING_LookUpUsernameLinkTests(): List<org.signal.libsignal.net.GrpcTestCase<org.signal.libsignal.internal.LookUpUsernameLinkArgs, org.signal.libsignal.internal.LookUpUsernameLinkOut>> {
    val ffiOut =
      NativeTesting.TESTING_LookUpUsernameLinkTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Object, Object, org.signal.libsignal.internal.LookUpUsernameLinkArgs, org.signal.libsignal.internal.LookUpUsernameLinkOut>({
        downcastFromObject<org.signal.libsignal.internal.LookUpUsernameLinkArgs>(it)
      }, { downcastFromObject<org.signal.libsignal.internal.LookUpUsernameLinkOut>(it) })(ffiOut)
  }

  public fun TESTING_MyNiceTypeEnum_identity(
    x: org.signal.libsignal.internal.MyNiceTypeEnum,
  ): org.signal.libsignal.internal.MyNiceTypeEnum {
    val ffi_x = (org.signal.libsignal.internal.MyNiceTypeEnum::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MyNiceTypeEnum_identity(
        ffi_x,
      )

    return downcastFromObject<org.signal.libsignal.internal.MyNiceTypeEnum>(ffiOut)
  }

  public fun TESTING_MyNiceTypeEnum_to_string(x: org.signal.libsignal.internal.MyNiceTypeEnum): String {
    val ffi_x = (org.signal.libsignal.internal.MyNiceTypeEnum::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MyNiceTypeEnum_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_MyNiceTypeSimpleEnum_identity(
    x: org.signal.libsignal.internal.MyNiceTypeSimpleEnum,
  ): org.signal.libsignal.internal.MyNiceTypeSimpleEnum {
    val ffi_x = (org.signal.libsignal.internal.MyNiceTypeSimpleEnum::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MyNiceTypeSimpleEnum_identity(
        ffi_x,
      )

    return downcastFromObject<org.signal.libsignal.internal.MyNiceTypeSimpleEnum>(ffiOut)
  }

  public fun TESTING_MyNiceTypeSimpleEnum_to_string(x: org.signal.libsignal.internal.MyNiceTypeSimpleEnum): String {
    val ffi_x = (org.signal.libsignal.internal.MyNiceTypeSimpleEnum::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MyNiceTypeSimpleEnum_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_MyNiceTypeStruct_identity(
    x: org.signal.libsignal.internal.MyNiceTypeStruct,
  ): org.signal.libsignal.internal.MyNiceTypeStruct {
    val ffi_x = (org.signal.libsignal.internal.MyNiceTypeStruct::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MyNiceTypeStruct_identity(
        ffi_x,
      )

    return downcastFromObject<org.signal.libsignal.internal.MyNiceTypeStruct>(ffiOut)
  }

  public fun TESTING_MyNiceTypeStruct_to_string(x: org.signal.libsignal.internal.MyNiceTypeStruct): String {
    val ffi_x = (org.signal.libsignal.internal.MyNiceTypeStruct::toFfiArgTypeObject)(x)
    val ffiOut =
      NativeTesting.TESTING_MyNiceTypeStruct_to_string(
        ffi_x,
      )

    return identity(ffiOut)
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

  public fun TESTING_RedeemBackupReceiptTests(): List<org.signal.libsignal.net.GrpcTestCase<ByteArray, org.signal.libsignal.internal.RedeemBackupReceiptOut>> {
    val ffiOut =
      NativeTesting.TESTING_RedeemBackupReceiptTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<ByteArray, Object, ByteArray, org.signal.libsignal.internal.RedeemBackupReceiptOut>({
        identity(it)
      }, { downcastFromObject<org.signal.libsignal.internal.RedeemBackupReceiptOut>(it) })(ffiOut)
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

  public fun TESTING_SubmitCallQualitySurveyTests(): List<org.signal.libsignal.net.GrpcTestCase<org.signal.libsignal.net.CallQualitySurvey, Void?>> {
    val ffiOut =
      NativeTesting.TESTING_SubmitCallQualitySurveyTests()

    return org.signal.libsignal.net.GrpcTestCase
      .resultConverter<Object, Void?, org.signal.libsignal.net.CallQualitySurvey, Void?>({
        downcastFromObject<org.signal.libsignal.net.CallQualitySurvey>(it)
      }, { identity(it) })(ffiOut)
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

  public fun TESTING_conversion_Float_identity(x: Float): Float {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_Float_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_Float_to_string(x: Float): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_Float_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_OptionalBytes_identity(x: ByteArray?): ByteArray? {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_OptionalBytes_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_OptionalBytes_to_string(x: ByteArray?): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_OptionalBytes_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_OptionalFloat_identity(x: Float?): Float? {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_OptionalFloat_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_OptionalFloat_to_string(x: Float?): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_OptionalFloat_to_string(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_OptionalString_identity(x: String?): String? {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_OptionalString_identity(
        ffi_x,
      )

    return identity(ffiOut)
  }

  public fun TESTING_conversion_OptionalString_to_string(x: String?): String {
    val ffi_x = identity(x)
    val ffiOut =
      NativeTesting.TESTING_conversion_OptionalString_to_string(
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
