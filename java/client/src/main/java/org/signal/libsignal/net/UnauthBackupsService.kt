//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.Native
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

public data class DeterministicRandomSeedUseOnlyForTesting(
  val seed: Long,
)

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
}
