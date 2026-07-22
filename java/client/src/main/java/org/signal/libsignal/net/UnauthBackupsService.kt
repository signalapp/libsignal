//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.flow.Flow
import org.signal.libsignal.internal.BridgeCopyBackupMediaItem
import org.signal.libsignal.internal.BridgeCopyBackupMediaOutcome
import org.signal.libsignal.internal.BridgeCopyBackupMediaResult
import org.signal.libsignal.internal.BridgeDeleteBackupMediaItem
import org.signal.libsignal.internal.BridgeMediaBackupInfo
import org.signal.libsignal.internal.BridgeMessageBackupInfo
import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.internal.wrapStream
import org.signal.libsignal.messagebackup.BackupKey
import org.signal.libsignal.protocol.ecc.ECPrivateKey
import org.signal.libsignal.zkgroup.GenericServerPublicParams
import org.signal.libsignal.zkgroup.backups.BackupAuthCredential
import java.util.Objects

/**
 * Either a [RequestUnauthorizedException] or [UploadTooLargeException]
 */
public sealed interface GetUploadFormError : BadRequestError

public data class BackupAuth(
  val credential: BackupAuthCredential,
  val serverKeys: GenericServerPublicParams,
  val signingKey: ECPrivateKey,
)

public data class BackupCdnCredentials(
  val headers: Map<String, String>,
) {
  public companion object {
    @Suppress("UNCHECKED_CAST")
    internal fun fromFfiHeaders(headers: Array<Object>): BackupCdnCredentials =
      BackupCdnCredentials((headers as Array<Pair<String, String>>).toMap())
  }
}

public data class MessageBackupInfo(
  /**
   * The base directory of the backup data on the CDN.
   *
   * Always non-empty, even if a backup has not actually been stored to the CDN. If a backup was
   * previously uploaded and has not expired, it can be found in [cdn] at
   * `/backupDir/backupName`.
   */
  val backupDir: String,
  /**
   * The CDN type where the message backup is stored. Media may be stored elsewhere.
   */
  val cdn: Int,
  /**
   * The location of the message backup on the CDN.
   *
   * Always non-empty, even if a backup has not actually been stored to the CDN.
   */
  val backupName: String,
) {
  public companion object {
    public fun fromInternal(it: BridgeMessageBackupInfo): MessageBackupInfo =
      MessageBackupInfo(
        backupDir = it.backupDir,
        cdn = it.cdn,
        backupName = it.backupName,
      )
  }
}

public data class MediaBackupInfo(
  /**
   * The base directory of the backup data on the CDN.
   *
   * Always non-empty, even if no media has been stored to the CDN or the credential is for a tier
   * that does not support media.
   */
  val backupDir: String,
  /**
   * The prefix path component for media objects on a CDN.
   *
   * Stored media for a `mediaId` can be found at `/backupDir/mediaDir/mediaId`, where the
   * `mediaId` is encoded in unpadded url-safe base64. Always non-empty, even if no media has been
   * stored to the CDN or the credential is for a tier that does not support media.
   */
  val mediaDir: String,
  /**
   * The amount of space used to store media, in bytes.
   */
  val usedSpace: Long,
) {
  public companion object {
    public fun fromInternal(it: BridgeMediaBackupInfo): MediaBackupInfo =
      MediaBackupInfo(
        backupDir = it.backupDir,
        mediaDir = it.mediaDir,
        usedSpace = it.usedSpace,
      )
  }
}

/**
 * A single item to copy from the attachment CDN to the backup CDN.
 *
 * `encryptionKey` is the combined HMAC + AES key from [BackupKey.deriveMediaEncryptionKey]
 * or [BackupKey.deriveThumbnailTransitEncryptionKey].
 */
public data class CopyBackupMediaItem(
  val sourceAttachmentCdn: Int,
  val sourceKey: String,
  val objectLength: Long,
  val mediaId: ByteArray,
  val encryptionKey: ByteArray,
) {
  override fun equals(other: Any?): Boolean {
    if (other !is CopyBackupMediaItem) {
      return false
    }
    return sourceAttachmentCdn == other.sourceAttachmentCdn &&
      sourceKey == other.sourceKey &&
      objectLength == other.objectLength &&
      mediaId.contentEquals(
        other.mediaId,
      ) &&
      encryptionKey.contentEquals(other.encryptionKey)
  }

  override fun hashCode(): Int =
    Objects.hash(
      sourceAttachmentCdn,
      sourceKey,
      objectLength,
      mediaId.contentHashCode(),
      encryptionKey.contentHashCode(),
    )
}

public sealed class CopyBackupMediaOutcome(
  public val mediaId: ByteArray,
) {
  public class Success(
    mediaId: ByteArray,
    public val cdn: Int,
  ) : CopyBackupMediaOutcome(mediaId)

  public class SourceNotFound(
    mediaId: ByteArray,
  ) : CopyBackupMediaOutcome(mediaId)

  public class WrongSourceLength(
    mediaId: ByteArray,
  ) : CopyBackupMediaOutcome(mediaId)

  public class OutOfSpace(
    mediaId: ByteArray,
  ) : CopyBackupMediaOutcome(mediaId)

  public companion object {
    // Public for testing, not intended for general use.
    @JvmStatic
    public fun fromFfi(value: BridgeCopyBackupMediaOutcome): CopyBackupMediaOutcome =
      when (value.result) {
        is BridgeCopyBackupMediaResult.Success -> Success(value.mediaId, value.result.cdn)
        is BridgeCopyBackupMediaResult.SourceNotFound -> SourceNotFound(value.mediaId)
        is BridgeCopyBackupMediaResult.WrongSourceLength -> WrongSourceLength(value.mediaId)
        is BridgeCopyBackupMediaResult.OutOfSpace -> OutOfSpace(value.mediaId)
      }
  }

  override fun equals(other: Any?): Boolean {
    if (javaClass != other?.javaClass) {
      return false
    }
    other as CopyBackupMediaOutcome
    if (!mediaId.contentEquals(other.mediaId)) {
      return false
    }
    return when (other) {
      is Success -> (this as Success).cdn == other.cdn
      is SourceNotFound, is WrongSourceLength, is OutOfSpace -> true
    }
  }

  override fun hashCode(): Int {
    // Omitting subclass fields is valid for hash codes,
    // and hashing this class is unlikely. Let's keep it simple.
    return mediaId.contentHashCode()
  }
}

public data class DeleteBackupMediaItem(
  val mediaId: ByteArray,
  val cdn: Int,
) {
  internal constructor(value: BridgeDeleteBackupMediaItem) : this(value.mediaId, value.cdn) {}

  override fun equals(other: Any?): Boolean {
    if (other !is DeleteBackupMediaItem) {
      return false
    }
    return mediaId.contentEquals(other.mediaId) && cdn == other.cdn
  }

  override fun hashCode(): Int = Objects.hash(mediaId.contentHashCode(), cdn)
}

public data class DeterministicRandomSeedUseOnlyForTesting(
  val seed: Long,
) {
  init {
    require(seed >= 0)
  }

  public companion object {
    public fun toFfi(seed: DeterministicRandomSeedUseOnlyForTesting?): Long = seed?.seed ?: -1
  }
}

public class UnauthBackupsService(
  private val connection: UnauthenticatedChatConnection,
) {
  /**
   * Get a messages backup attachment upload form
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [UploadTooLargeException] means that the uploadSize was
   * too large. A [RequestUnauthorizedException] means that the authorization failed.
   */
  public fun getUploadForm(
    auth: BackupAuth,
    uploadSize: Long,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<UploadForm, GetUploadFormError>> =
    try {
      require(uploadSize >= 0, { "uploadSize ($uploadSize) wasn't >= 0" })
      connection.runWithContextAndConnectionHandles { asyncCtx, conn ->
        auth.signingKey.guardedMap { signingKey ->
          Native
            .UnauthenticatedChatConnection_backup_get_upload_form(
              asyncCtx,
              conn,
              auth.credential.internalContentsForJNI,
              auth.serverKeys.internalContentsForJNI,
              signingKey,
              uploadSize,
              rngSeedForTesting?.seed ?: -1,
            ).mapWithCancellation(
              onSuccess = { RequestResult.Success(it as UploadForm) },
              onError = { err -> err.toRequestResult<GetUploadFormError>() },
            )
        }
      }
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Get an attachment backup attachment upload form
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [UploadTooLargeException] means that the uploadSize was
   * too large. A [RequestUnauthorizedException] means that the authorization failed.
   */
  public fun getMediaUploadForm(
    auth: BackupAuth,
    uploadSize: Long,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<UploadForm, GetUploadFormError>> =
    try {
      require(uploadSize >= 0, { "uploadSize ($uploadSize) wasn't >= 0" })
      connection.runWithContextAndConnectionHandles { asyncCtx, conn ->
        auth.signingKey.guardedMap { signingKey ->
          Native
            .UnauthenticatedChatConnection_backup_get_media_upload_form(
              asyncCtx,
              conn,
              auth.credential.internalContentsForJNI,
              auth.serverKeys.internalContentsForJNI,
              signingKey,
              uploadSize,
              rngSeedForTesting?.seed ?: -1,
            ).mapWithCancellation(
              onSuccess = { RequestResult.Success(it as UploadForm) },
              onError = { err -> err.toRequestResult<GetUploadFormError>() },
            )
        }
      }
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Sets the messages or media backup key based on `auth`.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [RequestUnauthorizedException] means that the authorization
   * failed; since the key is being updated, this suggests the credential in particular is invalid.
   */
  public fun setPublicKey(
    auth: BackupAuth,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<Unit, RequestUnauthorizedException>> =
    try {
      NativeNice
        .UnauthenticatedChatConnection_backup_set_public_key(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          credential = auth.credential,
          serverKeys = auth.serverKeys,
          signingKey = auth.signingKey,
          rng = rngSeedForTesting,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { it.toRequestResult<RequestUnauthorizedException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Fetches the credentials necessary to read from the given backup CDN.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [RequestUnauthorizedException] means that the authorization
   * failed.
   */
  public fun getCdnCredentials(
    auth: BackupAuth,
    cdn: Int,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<BackupCdnCredentials, RequestUnauthorizedException>> =
    try {
      NativeNice
        .UnauthenticatedChatConnection_backup_get_cdn_credentials(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          credential = auth.credential,
          serverKeys = auth.serverKeys,
          signingKey = auth.signingKey,
          cdn = cdn,
          rng = rngSeedForTesting,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { it.toRequestResult<RequestUnauthorizedException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Retrieves information about the currently stored message backup.
   *
   * The `auth` should be for a messages credential.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [RequestUnauthorizedException] means that the authorization
   * failed. Note that the server does not distinguish an invalid credential from a backup-id that
   * has never been provisioned: if [setPublicKey] has never been called for this backup-id, this
   * request also fails with [RequestUnauthorizedException]. Callers using this to check whether a
   * backup exists should treat that case as "backups not set up" rather than as a fatal error.
   */
  public fun getMessageBackupInfo(
    auth: BackupAuth,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<MessageBackupInfo, RequestUnauthorizedException>> =
    try {
      NativeNice
        .UnauthenticatedChatConnection_backup_get_message_backup_info(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          credential = auth.credential,
          serverKeys = auth.serverKeys,
          signingKey = auth.signingKey,
          rng = rngSeedForTesting,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(MessageBackupInfo.fromInternal(it)) },
          onError = { it.toRequestResult<RequestUnauthorizedException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Retrieves information about the currently stored media backup.
   *
   * The `auth` should be for a media credential.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [RequestUnauthorizedException] means that the authorization
   * failed. Note that the server does not distinguish an invalid credential from a backup-id that
   * has never been provisioned: if [setPublicKey] has never been called for this backup-id, this
   * request also fails with [RequestUnauthorizedException]. Callers using this to check whether a
   * backup exists should treat that case as "backups not set up" rather than as a fatal error.
   */
  public fun getMediaBackupInfo(
    auth: BackupAuth,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<MediaBackupInfo, RequestUnauthorizedException>> =
    try {
      NativeNice
        .UnauthenticatedChatConnection_backup_get_media_backup_info(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          credential = auth.credential,
          serverKeys = auth.serverKeys,
          signingKey = auth.signingKey,
          rng = rngSeedForTesting,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(MediaBackupInfo.fromInternal(it)) },
          onError = { it.toRequestResult<RequestUnauthorizedException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Fetches the credentials for connecting to SVR-B (a username/password pair).
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [RequestUnauthorizedException] means that the authorization
   * failed.
   */
  public fun getSvrBCredentials(
    auth: BackupAuth,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<Pair<String, String>, RequestUnauthorizedException>> =
    try {
      NativeNice
        .UnauthenticatedChatConnection_backup_get_svrb_credentials(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          credential = auth.credential,
          serverKeys = auth.serverKeys,
          signingKey = auth.signingKey,
          rng = rngSeedForTesting,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { it.toRequestResult<RequestUnauthorizedException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Indicates that the backup is still active.
   *
   * Clients must periodically upload new backups or perform a refresh. If a backup has not been
   * active for 30 days, it may be deleted.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [RequestUnauthorizedException] means that the authorization
   * failed.
   */
  public fun refresh(
    auth: BackupAuth,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<Unit, RequestUnauthorizedException>> =
    try {
      NativeNice
        .UnauthenticatedChatConnection_backup_refresh(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          credential = auth.credential,
          serverKeys = auth.serverKeys,
          signingKey = auth.signingKey,
          rng = rngSeedForTesting,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { it.toRequestResult<RequestUnauthorizedException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Deletes all backup metadata, objects, and stored public key.
   *
   * To use backups again, a public key must be resupplied.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [RequestUnauthorizedException] means that the authorization
   * failed.
   */
  public fun deleteAll(
    auth: BackupAuth,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<Unit, RequestUnauthorizedException>> =
    try {
      NativeNice
        .UnauthenticatedChatConnection_backup_delete_all(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          credential = auth.credential,
          serverKeys = auth.serverKeys,
          signingKey = auth.signingKey,
          rng = rngSeedForTesting,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { it.toRequestResult<RequestUnauthorizedException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Copy and re-encrypt media from the attachments CDN into the backup CDN.
   *
   * The original, already encrypted, attachments will be encrypted with the
   * provided key material before being copied. On retries, a particular destination media ID
   * must not be reused with a different source media key or different encryption parameters.
   *
   * The copy operation is not atomic and responses will be returned as copy operations complete
   * with detailed information about the outcome. If an error is encountered, not all requests
   * may be reflected in the responses. However, there is no need to retry the items that did
   * receive a response.
   *
   * The flow may be terminated at any time with the standard Signal network exceptions.
   * In addition, the flow may terminate with [RequestUnauthorizedException] if there are
   * authorization issues. You can use [Throwable.toRequestResult] to classify exceptions produced
   * by the flow similarly to the non-streaming endpoints. Large numbers of items may result in
   * multiple requests to the server, which means a `RequestUnauthorizedException` can happen in the
   * middle of the stream.
   *
   * The flow can only be collected once; trying to collect it multiple times will throw
   * [IllegalStateException].
   */
  public fun copyMedia(
    auth: BackupAuth,
    items: List<CopyBackupMediaItem>,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): Flow<CopyBackupMediaOutcome> {
    val stream =
      NativeNice.UnauthenticatedChatConnection_backup_copy_media(
        chat = connection,
        credential = auth.credential,
        serverKeys = auth.serverKeys,
        signingKey = auth.signingKey,
        items =
          items.map {
            BridgeCopyBackupMediaItem(
              sourceAttachmentCdn = it.sourceAttachmentCdn,
              sourceKey = it.sourceKey,
              objectLength = it.objectLength,
              mediaId = it.mediaId,
              encryptionKey = it.encryptionKey,
            )
          },
        rng = rngSeedForTesting,
      )
    return wrapStream(
      connection.tokioAsyncContext,
      stream,
      pull = { asyncRuntime, stream ->
        NativeNice.CopyBackupMediaStream_next(asyncRuntime, stream).thenApply { Pair(it.chunk, it.termination) }
      },
      convertItem = CopyBackupMediaOutcome::fromFfi,
      cancel = Native::CopyBackupMediaStream_cancel,
    )
  }

  /**
   * Delete media objects stored with this backup ID.
   *
   * The delete operation is not atomic and responses will be returned as delete operations
   * complete. If an error is encountered, not all requests  may be reflected in the responses.
   * However, there is no need to retry the items that did receive a response.
   *
   * The flow may be terminated at any time with the standard Signal network exceptions.
   * In addition, the flow may immediately terminate with [RequestUnauthorizedException]
   * if there are authorization issues. You can use [Throwable.toRequestResult] to classify
   * exceptions produced by the flow similarly to the non-streaming endpoints.
   *
   * The flow can only be collected once; trying to collect it multiple times will throw
   * [IllegalStateException].
   */
  public fun deleteMedia(
    auth: BackupAuth,
    items: List<DeleteBackupMediaItem>,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): Flow<DeleteBackupMediaItem> {
    val stream =
      NativeNice.UnauthenticatedChatConnection_backup_delete_media(
        chat = connection,
        credential = auth.credential,
        serverKeys = auth.serverKeys,
        signingKey = auth.signingKey,
        items =
          items.map {
            BridgeDeleteBackupMediaItem(
              mediaId = it.mediaId,
              cdn = it.cdn,
            )
          },
        rng = rngSeedForTesting,
      )
    return wrapStream(
      connection.tokioAsyncContext,
      stream,
      pull = { asyncRuntime, stream ->
        NativeNice.DeleteBackupMediaStream_next(asyncRuntime, stream).thenApply { Pair(it.chunk, it.termination) }
      },
      convertItem = ::DeleteBackupMediaItem,
      cancel = Native::DeleteBackupMediaStream_cancel,
    )
  }
}
