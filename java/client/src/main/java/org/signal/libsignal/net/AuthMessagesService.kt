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
   * [RequestResult.ApplicationError].
   */
  public fun getUploadForm(): CompletableFuture<RequestResult<UploadForm, Nothing>> =
    try {
      connection.runWithContextAndConnectionHandles { asyncCtx, conn ->
        Native
          .AuthenticatedChatConnection_get_upload_form(
            asyncCtx,
            conn,
          ).mapWithCancellation(
            onSuccess = { RequestResult.Success(it as UploadForm) },
            onError = { err -> err.toRequestResult() },
          )
      }
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}
