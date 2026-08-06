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
import org.signal.libsignal.internal.NativeNiceHelpers.mapPair

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

public data class CopyBackupMediaNextChunk(
  public val chunk: List<org.signal.libsignal.internal.BridgeCopyBackupMediaOutcome>,
  public val termination: Any?,
)

public data class DeleteBackupMediaNextChunk(
  public val chunk: List<org.signal.libsignal.internal.BridgeDeleteBackupMediaItem>,
  public val termination: Any?,
)

public data class LinkedDeviceInternal(
  public val id: org.signal.libsignal.protocol.DeviceId,
  public val encryptedName: ByteArray,
  public val lastSeen: java.time.Instant,
  public val registrationId: Int,
  public val createdAtCiphertext: ByteArray,
)

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

public object BridgeCopyBackupMediaOutcome_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    media_id: Any?,
    result: Any?,
  ): BridgeCopyBackupMediaOutcome =
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
  internal fun fromNative(cdn: Any?): BridgeCopyBackupMediaResult.Success =
    BridgeCopyBackupMediaResult.Success(
      cdn =
        identity(cdn as Int),
    )
}

public object BridgeCopyBackupMediaResult_SourceNotFound_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): BridgeCopyBackupMediaResult.SourceNotFound = BridgeCopyBackupMediaResult.SourceNotFound
}

public object BridgeCopyBackupMediaResult_WrongSourceLength_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): BridgeCopyBackupMediaResult.WrongSourceLength =
    BridgeCopyBackupMediaResult.WrongSourceLength
}

public object BridgeCopyBackupMediaResult_OutOfSpace_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(): BridgeCopyBackupMediaResult.OutOfSpace = BridgeCopyBackupMediaResult.OutOfSpace
}

public object BridgeDeleteBackupMediaItem_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    media_id: Any?,
    cdn: Any?,
  ): BridgeDeleteBackupMediaItem =
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
  ): BridgeMediaBackupInfo =
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
  ): BridgeMessageBackupInfo =
    BridgeMessageBackupInfo(
      backupDir =
        identity(backup_dir as String),
      cdn =
        identity(cdn as Int),
      backupName =
        identity(backup_name as String),
    )
}

public object CopyBackupMediaNextChunk_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    chunk: Any?,
    termination: Any?,
  ): CopyBackupMediaNextChunk =
    CopyBackupMediaNextChunk(
      chunk =
        mapBridgeVecReturn<Object, org.signal.libsignal.internal.BridgeCopyBackupMediaOutcome>({
          downcastFromObject<org.signal.libsignal.internal.BridgeCopyBackupMediaOutcome>(it)
        })(chunk as Array<*>),
      termination =
        identity(termination as Object?),
    )
}

public object DeleteBackupMediaNextChunk_ReturnConverter {
  @CalledFromNative
  @JvmStatic
  @JvmName("fromNative")
  internal fun fromNative(
    chunk: Any?,
    termination: Any?,
  ): DeleteBackupMediaNextChunk =
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
  ): LinkedDeviceInternal =
    LinkedDeviceInternal(
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
  ): ListMediaItem =
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
  ): ListMediaResponse =
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

  public fun AuthenticatedChatConnection_get_devices(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
  ): CompletableFuture<List<org.signal.libsignal.internal.LinkedDeviceInternal>> {
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
        mapBridgeVecReturn<Object, org.signal.libsignal.internal.LinkedDeviceInternal>({
          downcastFromObject<org.signal.libsignal.internal.LinkedDeviceInternal>(it)
        })(it)
      }
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
}
