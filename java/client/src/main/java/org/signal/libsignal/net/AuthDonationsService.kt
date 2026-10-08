//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.signal.libsignal.zkgroup.donation.DonationPermit
import org.signal.libsignal.zkgroup.donation.DonationPermitRequestContext

public class AuthDonationsService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Requests a batch of anonymous, single-use donation permits, one for each nonce in
   * [requestContext].
   *
   * The server's response is verified against [serverParams] before the permits are returned,
   * in the same order as the nonces in [requestContext].
   *
   * The server rate-limits each account by the number of permits requested, not the number of
   * requests. If the account doesn't have enough allowance left for the whole batch, nothing is
   * issued or used up and this fails with a [RequestResult.RetryableNetworkError] holding a
   * [RetryLaterException]. The retry delay is how long until the *full* batch would be allowed,
   * so asking for fewer permits may succeed sooner, even right away. A batch larger than the
   * server's maximum allowance will never succeed, no matter how long the caller waits.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun createDonationPermits(
    requestContext: DonationPermitRequestContext,
    serverParams: ServerPublicParams,
  ): CompletableFuture<RequestResult<List<DonationPermit>, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_create_donation_permits(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          requestContext = requestContext,
          serverParams = serverParams,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}
