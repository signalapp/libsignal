//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation

public class AuthAccountsService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Sets the registration lock secret for the authenticated account, given the account's SVR key
   * (which Signal clients historically call the "master key").
   *
   * Internally, we derive the registration lock secret from the SVR key and send only that secret.
   * The SVR key itself never leaves the device.
   *
   * While the registration lock is set, re-registering the account's phone number requires proving
   * knowledge of the secret.
   *
   * Only the account's primary device may set a registration lock.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun setRegistrationLock(svrKey: SvrKey): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_set_registration_lock(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          svrKey = svrKey.internalContentsForJNI,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Removes any registration lock from the authenticated account.
   *
   * This also succeeds if the account has no registration lock set, so a caller retrying a removal
   * sees the same result as the original call.
   *
   * Only the account's primary device may clear a registration lock.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun clearRegistrationLock(): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_clear_registration_lock(
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
   * Sets the registration recovery password for the authenticated account, given the account's SVR
   * key (which Signal clients historically call the "master key").
   *
   * Internally, we derive the registration recovery password from the SVR key and send only that
   * derived password. The SVR key itself never leaves the device.
   *
   * The registration recovery password lets the account re-register its phone number without SMS
   * verification. Any of the account's devices may set it.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun setRegistrationRecoveryPassword(svrKey: SvrKey): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_set_registration_recovery_password(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          svrKey = svrKey.internalContentsForJNI,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Sets whether the authenticated account may be discovered by phone number via the Contact
   * Discovery Service (CDS).
   *
   * If `false`, other users must discover this account by other means (e.g. by username).
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun setDiscoverableByPhoneNumber(discoverable: Boolean): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_set_discoverable_by_phone_number(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          discoverable = discoverable,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}
