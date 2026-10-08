//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.liftExceptions
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.signal.libsignal.zkgroup.donation.DonationPermit
import org.signal.libsignal.zkgroup.donation.DonationPermitRequestContext
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialPresentation

/**
 * How a redeemed badge should appear on the account's profile.
 */
public sealed class BadgeVisibility {
  // Must be kept in sync with BadgeVisibility in rust/bridge/shared/types/src/net/chat.rs.
  // The generated bridging code uses this type directly and refers to the subclasses by name.

  /**
   * Don't make the badge visible. A new badge starts out hidden, and a badge the account already
   * shows stays visible.
   */
  public data object DoNotSet : BadgeVisibility()

  /** Make the badge visible on the profile. */
  public data object SetVisible : BadgeVisibility()

  /** Make the badge visible on the profile as the primary badge. */
  public data object SetPrimary : BadgeVisibility()

  public companion object {
    /**
     * Picks the visibility for a client that tracks "show badges" and "make primary" as separate
     * flags. [isPrimary] is ignored when [isVisible] is false.
     */
    @JvmStatic
    public fun of(
      isVisible: Boolean,
      isPrimary: Boolean,
    ): BadgeVisibility =
      when {
        !isVisible -> DoNotSet
        isPrimary -> SetPrimary
        else -> SetVisible
      }
  }
}

public class AuthDonationsService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Redeems a donation receipt to add the corresponding badge to the account.
   *
   * After this succeeds, the account has the badge until the receipt's expiration time.
   * [visibility] controls whether it shows on the profile; see [BadgeVisibility].
   *
   * Redeeming the same receipt again for the same account succeeds. A receipt that was already
   * redeemed by a different account fails with a [ReceiptAlreadyRedeemedException].
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. An [InvalidReceiptException] means the receipt credential
   * presentation is invalid; a [ReceiptAlreadyRedeemedException] means the receipt was already
   * redeemed.
   */
  public fun redeemDonationReceipt(
    presentation: ReceiptCredentialPresentation,
    visibility: BadgeVisibility,
  ): CompletableFuture<RequestResult<Unit, RedeemDonationReceiptFailure>> =
    liftExceptions {
      NativeNice
        .AuthenticatedChatConnection_redeem_donation_receipt(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          presentation = presentation,
          visibility = visibility,
        )
    }.mapWithCancellation(
      onSuccess = { RequestResult.Success(Unit) },
      onError = { err -> err.toRequestResult<RedeemDonationReceiptFailure>() },
    )

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
    liftExceptions {
      NativeNice
        .AuthenticatedChatConnection_create_donation_permits(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          requestContext = requestContext,
          serverParams = serverParams,
        )
    }.mapWithCancellation(
      onSuccess = { RequestResult.Success(it) },
      onError = { err -> err.toRequestResult() },
    )
}

/** Either [InvalidReceiptException] or [ReceiptAlreadyRedeemedException]. */
public sealed interface RedeemDonationReceiptFailure : BadRequestError
