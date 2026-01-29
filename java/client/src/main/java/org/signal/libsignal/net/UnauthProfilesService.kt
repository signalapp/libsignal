//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.protocol.ServiceId

public class UnauthProfilesService(
  private val connection: UnauthenticatedChatConnection,
) {
  /**
   * Does an account with the given ACI or PNI exist?
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun accountExists(account: ServiceId): CompletableFuture<RequestResult<Boolean, Nothing>> =
    try {
      connection.runWithContextAndConnectionHandles { asyncCtx, conn ->
        Native
          .UnauthenticatedChatConnection_account_exists(
            asyncCtx,
            conn,
            account.toServiceIdFixedWidthBinary(),
          ).mapWithCancellation(
            onSuccess = { RequestResult.Success(it) },
            onError = { err -> err.toRequestResult() },
          )
      }
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}
