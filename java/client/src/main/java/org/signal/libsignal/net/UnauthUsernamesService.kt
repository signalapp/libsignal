//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.liftExceptions
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.usernames.Username
import org.signal.libsignal.usernames.UsernameHash
import java.util.UUID

public class UnauthUsernamesService(
  private val connection: UnauthenticatedChatConnection,
) {
  /**
   * Looks up a username hash on the service, like that computed by [Username.getHash].
   *
   * Produces the corresponding account's ACI, or `null` if the username doesn't correspond to an
   * account.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun lookUpUsernameHash(hash: UsernameHash): CompletableFuture<RequestResult<ServiceId.Aci?, Nothing>> =
    liftExceptions {
      connection
        .runWithContextAndConnectionHandles { asyncCtx, conn ->
          Native.UnauthenticatedChatConnection_look_up_username_hash(asyncCtx, conn, hash.internalContentsForJNI)
        }
    }.mapWithCancellation(
      onSuccess = { uuid -> RequestResult.Success(uuid?.let(ServiceId::Aci)) },
      onError = { err -> err.toRequestResult() },
    )

  /**
   * Looks up a username link on the service by UUID.
   *
   * Returns a decrypted, validated username, or `null` if the UUID does not correspond to a
   * username link (perhaps the user rotated their link).
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun lookUpUsernameLink(
    uuid: UUID,
    entropy: ByteArray,
  ): CompletableFuture<RequestResult<Username?, LookUpUsernameLinkFailure>> =
    liftExceptions {
      connection
        .runWithContextAndConnectionHandles { asyncCtx, conn ->
          Native.UnauthenticatedChatConnection_look_up_username_link(asyncCtx, conn, uuid, entropy)
        }
    }.mapWithCancellation(
      onSuccess = { pair ->
        if (pair == null) {
          RequestResult.Success(null)
        } else {
          RequestResult.Success(Username._withPrecomputedHash(pair.first, UsernameHash(pair.second)))
        }
      },
      onError = { err -> err.toRequestResult<LookUpUsernameLinkFailure>() },
    )
}
