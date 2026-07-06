//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.protocol.ecc.ECPrivateKey
import org.signal.libsignal.zkgroup.GenericServerPublicParams
import org.signal.libsignal.zkgroup.backups.BackupAuthCredential

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
}
