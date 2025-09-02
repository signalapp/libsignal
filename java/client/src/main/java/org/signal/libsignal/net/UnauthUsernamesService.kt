//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.protocol.ServiceId

public class UnauthUsernamesService(
  private val connection: UnauthenticatedChatConnection,
) {
  /**
   * Looks up a username hash on the service, like that computed by
   * [org.signal.libsignal.usernames.Username].
   *
   * Produces the corresponding account's ACI, or `null` if the username doesn't correspond to an
   * account.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun lookUpUsernameHash(hash: ByteArray): CompletableFuture<RequestResult<ServiceId.Aci?, Nothing>> =
    try {
      connection
        .runWithContextAndConnectionHandles { asyncCtx, conn ->
          Native.UnauthenticatedChatConnection_look_up_username_hash(asyncCtx, conn, hash)
        }.mapWithCancellation(
          onSuccess = { uuid -> RequestResult.Success(uuid?.let(ServiceId::Aci)) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}
