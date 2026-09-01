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

/*
// org.signal.libsignal.net.AuthCheckResult

public sealed class AuthCheckResult {
  public data object Match : AuthCheckResult()

  public data object NoMatch : AuthCheckResult()

  public data object Invalid : AuthCheckResult()
}

*/

public data class BridgeCopyBackupMediaItem(
  public val sourceAttachmentCdn: Int,
  public val sourceKey: String,
  public val objectLength: Long,
  public val mediaId: ByteArray,
  public val encryptionKey: ByteArray,
)

public data class BridgeCopyBackupMediaOutcome(
  public val mediaId: ByteArray,
  public val result: org.signal.libsignal.internal.BridgeCopyBackupMediaResult,
)

public sealed class BridgeCopyBackupMediaResult {
  public data class Success(
    public val cdn: Int,
  ) : BridgeCopyBackupMediaResult()

  public data object SourceNotFound : BridgeCopyBackupMediaResult()

  public data object WrongSourceLength : BridgeCopyBackupMediaResult()

  public data object OutOfSpace : BridgeCopyBackupMediaResult()
}

public data class BridgeDeleteBackupMediaItem(
  public val mediaId: ByteArray,
  public val cdn: Int,
)

public data class BridgeMediaBackupInfo(
  public val backupDir: String,
  public val mediaDir: String,
  public val usedSpace: Long,
)

public data class BridgeMessageBackupInfo(
  public val backupDir: String,
  public val cdn: Int,
  public val backupName: String,
)

public data class BridgePreKeyCounts(
  public val aciEcPreKeyCount: Int,
  public val aciKemPreKeyCount: Int,
  public val pniEcPreKeyCount: Int,
  public val pniKemPreKeyCount: Int,
)

/*
// org.signal.libsignal.net.CallQualitySurvey

public data class CallQualitySurveyInternal(
  public val userSatisfied: Boolean,
  public val callQualityIssues: List<String>,
  public val additionalIssuesDescription: String?,
  public val debugLogUrl: String?,
  public val startTimestamp: java.time.Instant,
  public val endTimestamp: java.time.Instant,
  public val callType: String,
  public val success: Boolean,
  public val callEndReason: String,
  public val connectionRttMedian: Float?,
  public val audioRttMedian: Float?,
  public val videoRttMedian: Float?,
  public val audioRecvJitterMedian: Float?,
  public val videoRecvJitterMedian: Float?,
  public val audioSendJitterMedian: Float?,
  public val videoSendJitterMedian: Float?,
  public val audioRecvPacketLossFraction: Float?,
  public val videoRecvPacketLossFraction: Float?,
  public val audioSendPacketLossFraction: Float?,
  public val videoSendPacketLossFraction: Float?,
  public val callTelemetry: ByteArray?,
  public val callIdHash: ByteArray?,
)

*/

public data class CopyBackupMediaNextChunk(
  public val chunk: List<org.signal.libsignal.internal.BridgeCopyBackupMediaOutcome>,
  public val termination: Any?,
)

public data class CurrencyConversionsInternal(
  public val timestampMs: java.time.Instant,
  public val currencies: List<org.signal.libsignal.internal.CurrencyInternal>,
)

public data class CurrencyInternal(
  public val base: String,
  public val conversions: List<Pair<String, String>>,
)

public data class DeleteBackupMediaNextChunk(
  public val chunk: List<org.signal.libsignal.internal.BridgeDeleteBackupMediaItem>,
  public val termination: Any?,
)

/*
// org.signal.libsignal.net.LinkedDevice

public data class LinkedDeviceInternal(
  public val id: org.signal.libsignal.protocol.DeviceId,
  public val encryptedName: ByteArray,
  public val lastSeen: java.time.Instant,
  public val registrationId: Int,
  public val createdAtCiphertext: ByteArray,
)

*/

public data class ListMediaItem(
  public val cdn: Int,
  public val mediaId: ByteArray,
  public val objectLength: Long,
)

public data class ListMediaResponse(
  public val items: List<org.signal.libsignal.internal.ListMediaItem>,
  public val backupDir: String,
  public val mediaDir: String,
  public val cursor: String?,
)

public object AuthCheckResult_Match_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = org.signal.libsignal.net.AuthCheckResult.Match
}

public object AuthCheckResult_NoMatch_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = org.signal.libsignal.net.AuthCheckResult.NoMatch
}

public object AuthCheckResult_Invalid_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = org.signal.libsignal.net.AuthCheckResult.Invalid
}

public object BridgeCopyBackupMediaOutcome_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    media_id: Any?,
    result: Any?,
  ): Any? =
    BridgeCopyBackupMediaOutcome(
      mediaId =
        identity(media_id as ByteArray),
      result =
        downcastFromObject<org.signal.libsignal.internal.BridgeCopyBackupMediaResult>(result as Object),
    )
}

public object BridgeCopyBackupMediaResult_Success_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(cdn: Any?): Any? =
    BridgeCopyBackupMediaResult.Success(
      cdn =
        identity(cdn as Int),
    )
}

public object BridgeCopyBackupMediaResult_SourceNotFound_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = BridgeCopyBackupMediaResult.SourceNotFound
}

public object BridgeCopyBackupMediaResult_WrongSourceLength_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = BridgeCopyBackupMediaResult.WrongSourceLength
}

public object BridgeCopyBackupMediaResult_OutOfSpace_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): Any? = BridgeCopyBackupMediaResult.OutOfSpace
}

public object BridgeDeleteBackupMediaItem_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    media_id: Any?,
    cdn: Any?,
  ): Any? =
    BridgeDeleteBackupMediaItem(
      mediaId =
        identity(media_id as ByteArray),
      cdn =
        identity(cdn as Int),
    )
}

public object BridgeMediaBackupInfo_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    backup_dir: Any?,
    media_dir: Any?,
    used_space: Any?,
  ): Any? =
    BridgeMediaBackupInfo(
      backupDir =
        identity(backup_dir as String),
      mediaDir =
        identity(media_dir as String),
      usedSpace =
        identity(used_space as Long),
    )
}

public object BridgeMessageBackupInfo_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    backup_dir: Any?,
    cdn: Any?,
    backup_name: Any?,
  ): Any? =
    BridgeMessageBackupInfo(
      backupDir =
        identity(backup_dir as String),
      cdn =
        identity(cdn as Int),
      backupName =
        identity(backup_name as String),
    )
}

public object BridgePreKeyCounts_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    aci_ec_pre_key_count: Any?,
    aci_kem_pre_key_count: Any?,
    pni_ec_pre_key_count: Any?,
    pni_kem_pre_key_count: Any?,
  ): Any? =
    BridgePreKeyCounts(
      aciEcPreKeyCount =
        identity(aci_ec_pre_key_count as Int),
      aciKemPreKeyCount =
        identity(aci_kem_pre_key_count as Int),
      pniEcPreKeyCount =
        identity(pni_ec_pre_key_count as Int),
      pniKemPreKeyCount =
        identity(pni_kem_pre_key_count as Int),
    )
}

public object CopyBackupMediaNextChunk_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    chunk: Any?,
    termination: Any?,
  ): Any? =
    CopyBackupMediaNextChunk(
      chunk =
        mapBridgeVecReturn<Object, org.signal.libsignal.internal.BridgeCopyBackupMediaOutcome>({
          downcastFromObject<org.signal.libsignal.internal.BridgeCopyBackupMediaOutcome>(it)
        })(chunk as Array<*>),
      termination =
        identity(termination as Object?),
    )
}

public object CurrencyConversionsInternal_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    timestamp_ms: Any?,
    currencies: Any?,
  ): Any? =
    CurrencyConversionsInternal(
      timestampMs =
        (java.time.Instant::ofEpochMilli)(timestamp_ms as Long),
      currencies =
        mapBridgeVecReturn<Object, org.signal.libsignal.internal.CurrencyInternal>({
          downcastFromObject<org.signal.libsignal.internal.CurrencyInternal>(it)
        })(currencies as Array<*>),
    )
}

public object CurrencyInternal_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    base: Any?,
    conversions: Any?,
  ): Any? =
    CurrencyInternal(
      base =
        identity(base as String),
      conversions =
        mapBridgeVecReturn<Pair<String, String>, Pair<String, String>>({
          mapPair<String, String, String, String>({ identity(it) }, { identity(it) })(it)
        })(conversions as Array<*>),
    )
}

public object DeleteBackupMediaNextChunk_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    chunk: Any?,
    termination: Any?,
  ): Any? =
    DeleteBackupMediaNextChunk(
      chunk =
        mapBridgeVecReturn<Object, org.signal.libsignal.internal.BridgeDeleteBackupMediaItem>({
          downcastFromObject<org.signal.libsignal.internal.BridgeDeleteBackupMediaItem>(it)
        })(chunk as Array<*>),
      termination =
        identity(termination as Object?),
    )
}

public object LinkedDeviceInternal_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    id: Any?,
    encrypted_name: Any?,
    last_seen: Any?,
    registration_id: Any?,
    created_at_ciphertext: Any?,
  ): Any? =
    org.signal.libsignal.net.LinkedDevice(
      id =
        identity(id as org.signal.libsignal.protocol.DeviceId),
      encryptedName =
        identity(encrypted_name as ByteArray),
      lastSeen =
        (java.time.Instant::ofEpochMilli)(last_seen as Long),
      registrationId =
        identity(registration_id as Int),
      createdAtCiphertext =
        identity(created_at_ciphertext as ByteArray),
    )
}

public object ListMediaItem_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    cdn: Any?,
    media_id: Any?,
    object_length: Any?,
  ): Any? =
    ListMediaItem(
      cdn =
        identity(cdn as Int),
      mediaId =
        identity(media_id as ByteArray),
      objectLength =
        identity(object_length as Long),
    )
}

public object ListMediaResponse_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    items: Any?,
    backup_dir: Any?,
    media_dir: Any?,
    cursor: Any?,
  ): Any? =
    ListMediaResponse(
      items =
        mapBridgeVecReturn<Object, org.signal.libsignal.internal.ListMediaItem>({
          downcastFromObject<org.signal.libsignal.internal.ListMediaItem>(it)
        })(items as Array<*>),
      backupDir =
        identity(backup_dir as String),
      mediaDir =
        identity(media_dir as String),
      cursor =
        identity(cursor as String?),
    )
}

@CalledFromNative
@Suppress("ktlint:standard:backing-property-naming")
public class BridgeCopyBackupMediaItem_FfiArgType {
  @CalledFromNative
  internal val source_attachment_cdn: Int

  @CalledFromNative
  internal val source_key: Any?

  @CalledFromNative
  internal val object_length: Long

  @CalledFromNative
  internal val media_id: Any?

  @CalledFromNative
  internal val encryption_key: Any?
  internal constructor(
    source_attachment_cdn: Int,
    source_key: Any?,
    object_length: Long,
    media_id: Any?,
    encryption_key: Any?,
  ) {
    this.source_attachment_cdn = source_attachment_cdn
    this.source_key = source_key
    this.object_length = object_length
    this.media_id = media_id
    this.encryption_key = encryption_key
  }
}

public fun BridgeCopyBackupMediaItem.toFfiArgType(): BridgeCopyBackupMediaItem_FfiArgType =
  BridgeCopyBackupMediaItem_FfiArgType(
    source_attachment_cdn = identity(sourceAttachmentCdn),
    source_key = identity(sourceKey),
    object_length = identity(objectLength),
    media_id = identity(mediaId),
    encryption_key = identity(encryptionKey),
  )

public fun BridgeCopyBackupMediaItem.toFfiArgTypeObject(): Object = convertToObject(this.toFfiArgType())

@CalledFromNative
@Suppress("ktlint:standard:backing-property-naming")
public class BridgeDeleteBackupMediaItem_FfiArgType {
  @CalledFromNative
  internal val media_id: Any?

  @CalledFromNative
  internal val cdn: Int
  internal constructor(
    media_id: Any?,
    cdn: Int,
  ) {
    this.media_id = media_id
    this.cdn = cdn
  }
}

public fun BridgeDeleteBackupMediaItem.toFfiArgType(): BridgeDeleteBackupMediaItem_FfiArgType =
  BridgeDeleteBackupMediaItem_FfiArgType(
    media_id = identity(mediaId),
    cdn = identity(cdn),
  )

public fun BridgeDeleteBackupMediaItem.toFfiArgTypeObject(): Object = convertToObject(this.toFfiArgType())

@CalledFromNative
@Suppress("ktlint:standard:backing-property-naming")
public class CallQualitySurveyInternal_FfiArgType {
  @CalledFromNative
  internal val user_satisfied: Boolean

  @CalledFromNative
  internal val call_quality_issues: Any?

  @CalledFromNative
  internal val additional_issues_description: Any?

  @CalledFromNative
  internal val debug_log_url: Any?

  @CalledFromNative
  internal val start_timestamp: Long

  @CalledFromNative
  internal val end_timestamp: Long

  @CalledFromNative
  internal val call_type: Any?

  @CalledFromNative
  internal val success: Boolean

  @CalledFromNative
  internal val call_end_reason: Any?

  @CalledFromNative
  internal val connection_rtt_median: Any?

  @CalledFromNative
  internal val audio_rtt_median: Any?

  @CalledFromNative
  internal val video_rtt_median: Any?

  @CalledFromNative
  internal val audio_recv_jitter_median: Any?

  @CalledFromNative
  internal val video_recv_jitter_median: Any?

  @CalledFromNative
  internal val audio_send_jitter_median: Any?

  @CalledFromNative
  internal val video_send_jitter_median: Any?

  @CalledFromNative
  internal val audio_recv_packet_loss_fraction: Any?

  @CalledFromNative
  internal val video_recv_packet_loss_fraction: Any?

  @CalledFromNative
  internal val audio_send_packet_loss_fraction: Any?

  @CalledFromNative
  internal val video_send_packet_loss_fraction: Any?

  @CalledFromNative
  internal val call_telemetry: Any?

  @CalledFromNative
  internal val call_id_hash: Any?
  internal constructor(
    user_satisfied: Boolean,
    call_quality_issues: Any?,
    additional_issues_description: Any?,
    debug_log_url: Any?,
    start_timestamp: Long,
    end_timestamp: Long,
    call_type: Any?,
    success: Boolean,
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
  ) {
    this.user_satisfied = user_satisfied
    this.call_quality_issues = call_quality_issues
    this.additional_issues_description = additional_issues_description
    this.debug_log_url = debug_log_url
    this.start_timestamp = start_timestamp
    this.end_timestamp = end_timestamp
    this.call_type = call_type
    this.success = success
    this.call_end_reason = call_end_reason
    this.connection_rtt_median = connection_rtt_median
    this.audio_rtt_median = audio_rtt_median
    this.video_rtt_median = video_rtt_median
    this.audio_recv_jitter_median = audio_recv_jitter_median
    this.video_recv_jitter_median = video_recv_jitter_median
    this.audio_send_jitter_median = audio_send_jitter_median
    this.video_send_jitter_median = video_send_jitter_median
    this.audio_recv_packet_loss_fraction = audio_recv_packet_loss_fraction
    this.video_recv_packet_loss_fraction = video_recv_packet_loss_fraction
    this.audio_send_packet_loss_fraction = audio_send_packet_loss_fraction
    this.video_send_packet_loss_fraction = video_send_packet_loss_fraction
    this.call_telemetry = call_telemetry
    this.call_id_hash = call_id_hash
  }
}

public fun org.signal.libsignal.net.CallQualitySurvey.toFfiArgType(): CallQualitySurveyInternal_FfiArgType =
  CallQualitySurveyInternal_FfiArgType(
    user_satisfied = identity(userSatisfied),
    call_quality_issues =
      mapBridgeVecArg<String, String>({
        identity(it)
      })(callQualityIssues),
    additional_issues_description = identity(additionalIssuesDescription),
    debug_log_url = identity(debugLogUrl),
    start_timestamp = (java.time.Instant::toEpochMilli)(startTimestamp),
    end_timestamp = (java.time.Instant::toEpochMilli)(endTimestamp),
    call_type = identity(callType),
    success = identity(success),
    call_end_reason = identity(callEndReason),
    connection_rtt_median = identity(connectionRttMedian),
    audio_rtt_median = identity(audioRttMedian),
    video_rtt_median = identity(videoRttMedian),
    audio_recv_jitter_median = identity(audioRecvJitterMedian),
    video_recv_jitter_median = identity(videoRecvJitterMedian),
    audio_send_jitter_median = identity(audioSendJitterMedian),
    video_send_jitter_median = identity(videoSendJitterMedian),
    audio_recv_packet_loss_fraction = identity(audioRecvPacketLossFraction),
    video_recv_packet_loss_fraction = identity(videoRecvPacketLossFraction),
    audio_send_packet_loss_fraction = identity(audioSendPacketLossFraction),
    video_send_packet_loss_fraction = identity(videoSendPacketLossFraction),
    call_telemetry = identity(callTelemetry),
    call_id_hash = identity(callIdHash),
  )

public fun org.signal.libsignal.net.CallQualitySurvey.toFfiArgTypeObject(): Object =
  convertToObject(this.toFfiArgType())

public object NativeNice {
  public fun AuthenticatedChatConnection_clear_push_token(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_clear_push_token(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_clear_registration_lock(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_clear_registration_lock(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_confirm_username(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
    username: String,
    usernameCiphertext: ByteArray,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<java.util.UUID> {
    val ffi_chat = identity(chat)
    val ffi_username = identity(username)
    val ffi_username_ciphertext = identity(usernameCiphertext)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_confirm_username(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_username,
          ffi_username_ciphertext,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_delete_account(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_delete_account(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_delete_username_hash(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_delete_username_hash(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_delete_username_link(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_delete_username_link(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_get_currency_conversions(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
  ): CompletableFuture<org.signal.libsignal.internal.CurrencyConversionsInternal> {
    val ffi_chat = identity(chat)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_get_currency_conversions(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply { downcastFromObject<org.signal.libsignal.internal.CurrencyConversionsInternal>(it) }
  }

  public fun AuthenticatedChatConnection_get_devices(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
  ): CompletableFuture<List<org.signal.libsignal.net.LinkedDevice>> {
    val ffi_chat = identity(chat)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_get_devices(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply {
        mapBridgeVecReturn<Object, org.signal.libsignal.net.LinkedDevice>({
          downcastFromObject<org.signal.libsignal.net.LinkedDevice>(it)
        })(it)
      }
  }

  public fun AuthenticatedChatConnection_get_pre_key_count(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
  ): CompletableFuture<org.signal.libsignal.internal.BridgePreKeyCounts> {
    val ffi_chat = identity(chat)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_get_pre_key_count(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply { downcastFromObject<org.signal.libsignal.internal.BridgePreKeyCounts>(it) }
  }

  public fun AuthenticatedChatConnection_redeem_backup_receipt(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
    presentation: org.signal.libsignal.zkgroup.receipts.ReceiptCredentialPresentation,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_presentation =
      (org.signal.libsignal.zkgroup.internal.ByteArray::getInternalContentsForJNI)(presentation)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_redeem_backup_receipt(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_presentation,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_remove_device(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
    deviceId: org.signal.libsignal.protocol.DeviceId,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_device_id = identity(deviceId)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_remove_device(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_device_id,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_reserve_username_hash(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
    usernameHashes: List<ByteArray>,
  ): CompletableFuture<ByteArray> {
    val ffi_chat = identity(chat)
    val ffi_username_hashes = mapBridgeVecArg<ByteArray, ByteArray>({ identity(it) })(usernameHashes)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_reserve_username_hash(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_username_hashes,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_set_device_name(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
    deviceId: org.signal.libsignal.protocol.DeviceId,
    encryptedName: ByteArray,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_device_id = identity(deviceId)
    val ffi_encrypted_name = identity(encryptedName)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_set_device_name(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_device_id,
          ffi_encrypted_name,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_set_discoverable_by_phone_number(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
    discoverable: Boolean,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_discoverable = identity(discoverable)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_set_discoverable_by_phone_number(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_discoverable,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_set_push_token_fcm(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
    fcmToken: String,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_fcm_token = identity(fcmToken)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_set_push_token_fcm(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_fcm_token,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_set_registration_lock(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
    svrKey: ByteArray,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_svr_key = identity(svrKey)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_set_registration_lock(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_svr_key,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_set_registration_recovery_password(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
    svrKey: ByteArray,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_svr_key = identity(svrKey)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_set_registration_recovery_password(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_svr_key,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun AuthenticatedChatConnection_set_username_link(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
    usernameCiphertext: ByteArray,
    keepLinkHandle: Boolean,
  ): CompletableFuture<java.util.UUID> {
    val ffi_chat = identity(chat)
    val ffi_username_ciphertext = identity(usernameCiphertext)
    val ffi_keep_link_handle = identity(keepLinkHandle)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_set_username_link(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_username_ciphertext,
          ffi_keep_link_handle,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun CopyBackupMediaStream_next(
    asyncCtx: TokioAsyncContext,
    stream: org.signal.libsignal.net.internal.CopyBackupMediaStream,
  ): CompletableFuture<org.signal.libsignal.internal.CopyBackupMediaNextChunk> {
    val ffi_stream = identity(stream)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.CopyBackupMediaStream_next(
          asyncCtxHandle.nativeHandle(),
          ffi_stream,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply { downcastFromObject<org.signal.libsignal.internal.CopyBackupMediaNextChunk>(it) }
  }

  public fun DeleteBackupMediaStream_next(
    asyncCtx: TokioAsyncContext,
    stream: org.signal.libsignal.net.internal.DeleteBackupMediaStream,
  ): CompletableFuture<org.signal.libsignal.internal.DeleteBackupMediaNextChunk> {
    val ffi_stream = identity(stream)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.DeleteBackupMediaStream_next(
          asyncCtxHandle.nativeHandle(),
          ffi_stream,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply { downcastFromObject<org.signal.libsignal.internal.DeleteBackupMediaNextChunk>(it) }
  }

  public fun SvrKey_DeriveLoggingKey(svrKey: ByteArray): ByteArray {
    val ffi_svr_key = identity(svrKey)
    val ffiOut =
      Native.SvrKey_DeriveLoggingKey(
        ffi_svr_key,
      )

    return identity(ffiOut)
  }

  public fun SvrKey_DeriveRegistrationLock(svrKey: ByteArray): ByteArray {
    val ffi_svr_key = identity(svrKey)
    val ffiOut =
      Native.SvrKey_DeriveRegistrationLock(
        ffi_svr_key,
      )

    return identity(ffiOut)
  }

  public fun SvrKey_DeriveRegistrationRecoveryPassword(svrKey: ByteArray): ByteArray {
    val ffi_svr_key = identity(svrKey)
    val ffiOut =
      Native.SvrKey_DeriveRegistrationRecoveryPassword(
        ffi_svr_key,
      )

    return identity(ffiOut)
  }

  public fun SvrKey_DeriveStorageServiceKey(svrKey: ByteArray): ByteArray {
    val ffi_svr_key = identity(svrKey)
    val ffiOut =
      Native.SvrKey_DeriveStorageServiceKey(
        ffi_svr_key,
      )

    return identity(ffiOut)
  }

  public fun UnauthenticatedChatConnection_account_exists(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    account: org.signal.libsignal.protocol.ServiceId,
  ): CompletableFuture<Boolean> {
    val ffi_chat = identity(chat)
    val ffi_account = (org.signal.libsignal.protocol.ServiceId::toServiceIdFixedWidthBinary)(account)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_account_exists(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_account,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun UnauthenticatedChatConnection_backup_copy_media(
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    items: List<org.signal.libsignal.internal.BridgeCopyBackupMediaItem>,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): org.signal.libsignal.net.internal.CopyBackupMediaStream {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_items =
      mapBridgeVecArg<Object, org.signal.libsignal.internal.BridgeCopyBackupMediaItem>({
        (org.signal.libsignal.internal.BridgeCopyBackupMediaItem::toFfiArgTypeObject)(it)
      })(items)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      Native.UnauthenticatedChatConnection_backup_copy_media(
        ffi_chat,
        ffi_credential,
        ffi_server_keys,
        ffi_signing_key,
        ffi_items,
        ffi_rng,
      )

    return org.signal.libsignal.net.internal
      .CopyBackupMediaStream(ffiOut)
  }

  public fun UnauthenticatedChatConnection_backup_delete_all(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_delete_all(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun UnauthenticatedChatConnection_backup_delete_media(
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    items: List<org.signal.libsignal.internal.BridgeDeleteBackupMediaItem>,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): org.signal.libsignal.net.internal.DeleteBackupMediaStream {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_items =
      mapBridgeVecArg<Object, org.signal.libsignal.internal.BridgeDeleteBackupMediaItem>({
        (org.signal.libsignal.internal.BridgeDeleteBackupMediaItem::toFfiArgTypeObject)(it)
      })(items)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      Native.UnauthenticatedChatConnection_backup_delete_media(
        ffi_chat,
        ffi_credential,
        ffi_server_keys,
        ffi_signing_key,
        ffi_items,
        ffi_rng,
      )

    return org.signal.libsignal.net.internal
      .DeleteBackupMediaStream(ffiOut)
  }

  public fun UnauthenticatedChatConnection_backup_get_cdn_credentials(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    cdn: Int,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<org.signal.libsignal.net.BackupCdnCredentials> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_cdn = identity(cdn)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_get_cdn_credentials(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_cdn,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply {
        org.signal.libsignal.net.BackupCdnCredentials
          .fromFfiHeaders(it)
      }
  }

  public fun UnauthenticatedChatConnection_backup_get_media_backup_info(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<org.signal.libsignal.internal.BridgeMediaBackupInfo> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_get_media_backup_info(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply { downcastFromObject<org.signal.libsignal.internal.BridgeMediaBackupInfo>(it) }
  }

  public fun UnauthenticatedChatConnection_backup_get_message_backup_info(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<org.signal.libsignal.internal.BridgeMessageBackupInfo> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_get_message_backup_info(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply { downcastFromObject<org.signal.libsignal.internal.BridgeMessageBackupInfo>(it) }
  }

  public fun UnauthenticatedChatConnection_backup_get_svrb_credentials(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<Pair<String, String>> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_get_svrb_credentials(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply { mapPair<String, String, String, String>({ identity(it) }, { identity(it) })(it) }
  }

  public fun UnauthenticatedChatConnection_backup_list_media(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    cursor: String,
    limit: Int,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<org.signal.libsignal.internal.ListMediaResponse> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_cursor = identity(cursor)
    val ffi_limit = identity(limit)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_list_media(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_cursor,
          ffi_limit,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply { downcastFromObject<org.signal.libsignal.internal.ListMediaResponse>(it) }
  }

  public fun UnauthenticatedChatConnection_backup_refresh(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_refresh(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun UnauthenticatedChatConnection_backup_set_public_key(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_set_public_key(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun UnauthenticatedChatConnection_check_svr_credentials(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    number: String,
    credentials: List<String>,
  ): CompletableFuture<List<Pair<String, org.signal.libsignal.net.AuthCheckResult>>> {
    val ffi_chat = identity(chat)
    val ffi_number = identity(number)
    val ffi_credentials = mapBridgeVecArg<String, String>({ identity(it) })(credentials)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_check_svr_credentials(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_number,
          ffi_credentials,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply {
        mapBridgeVecReturn<Pair<String, Object>, Pair<String, org.signal.libsignal.net.AuthCheckResult>>({
          mapPair<String, Object, String, org.signal.libsignal.net.AuthCheckResult>({
            identity(it)
          }, { downcastFromObject<org.signal.libsignal.net.AuthCheckResult>(it) })(it)
        })(it)
      }
  }

  public fun UnauthenticatedChatConnection_submit_call_quality_survey(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    survey: org.signal.libsignal.net.CallQualitySurvey,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_survey = (org.signal.libsignal.net.CallQualitySurvey::toFfiArgTypeObject)(survey)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_submit_call_quality_survey(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_survey,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }
}
