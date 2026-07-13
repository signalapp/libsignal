//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation
import java.util.UUID

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

  /**
   * For the given encrypted username, generate a username link handle. The username link handle
   * can be used to lookup the encrypted username.
   *
   * An account can only have one username link at a time; this endpoint overwrites the previous
   * encrypted username if there was one.
   *
   * @param usernameCiphertext must be between 1 and 128 bytes
   * @param keepLinkHandle If true and the account already had an encrypted username stored, the existing link handle
   * will be reused. Otherwise, a new link handle will be created.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [UsernameNotSetException] indicates that the account
   * doesn't have a username set.
   */
  public fun setUsernameLink(
    usernameCiphertext: ByteArray,
    keepLinkHandle: Boolean,
  ): CompletableFuture<RequestResult<UUID, UsernameNotSetException>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_set_username_link(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          usernameCiphertext = usernameCiphertext,
          keepLinkHandle = keepLinkHandle,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err -> err.toRequestResult<UsernameNotSetException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Clears the current username hash, ciphertext, and link for the authenticated account.
   *
   * This also succeeds if the account has no username set, so a caller retrying a deletion sees
   * the same result as the original call.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun deleteUsernameHash(): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_delete_username_hash(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Clears any username link associated with the authenticated account.
   *
   * The previously stored encrypted username is deleted and the link handle is deactivated; the
   * account's username hash (if any) is left in place. This also succeeds if the account has no
   * username link, so a caller retrying a deletion sees the same result as the original call.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun deleteUsernameLink(): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_delete_username_link(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}
