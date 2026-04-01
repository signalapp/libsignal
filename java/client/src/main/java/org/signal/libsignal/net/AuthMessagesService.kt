//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.mapWithCancellation

public class AuthMessagesService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Get an attachment upload form
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [UploadTooLargeException] means that the uploadSize was
   * too large.
   */
  public fun getUploadForm(uploadSize: Long): CompletableFuture<RequestResult<UploadForm, UploadTooLargeException>> =
    try {
      require(uploadSize >= 0, { "uploadSize ($uploadSize) wasn't >= 0" })
      connection.runWithContextAndConnectionHandles { asyncCtx, conn ->
        Native
          .AuthenticatedChatConnection_get_upload_form(
            asyncCtx,
            conn,
            uploadSize,
          ).mapWithCancellation(
            onSuccess = { RequestResult.Success(it as UploadForm) },
            onError = { err -> err.toRequestResult<UploadTooLargeException>() },
          )
      }
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}
