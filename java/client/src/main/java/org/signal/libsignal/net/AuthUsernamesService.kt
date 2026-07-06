//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation

/**
 * A 32-byte hash of a username
 */
public typealias UsernameHash = ByteArray

public class AuthUsernamesService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Given a prioritized list of between 1 and 20 username hashes, try reserving them (in order)
   *
   * The first successfully reserved hash will be returned.

   * @param hashes Must contain between 1 and 20 usernames
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [UsernameNotAvailableException] indicates that none of the
   * usernames were available.
   */
  public fun reserveUsernameHash(
    usernameHashes: List<UsernameHash>,
  ): CompletableFuture<RequestResult<UsernameHash, UsernameNotAvailableException>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_reserve_username_hash(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          usernameHashes = usernameHashes,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err -> err.toRequestResult<UsernameNotAvailableException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}
