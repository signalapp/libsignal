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
import org.signal.libsignal.zkgroup.receipts.ReceiptCredential
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialRequestContext

public class UnauthSubscriptionsService(
  private val connection: UnauthenticatedChatConnection,
) {
  /**
   * Obtain a ZK receipt credential for an active subscription.
   * The receipt credential can then be used to obtain an entitlement (e.g. a badge or backup tier).
   *
   * Retries must use an identical `receiptCredentialRequestContext`. After successfully receiving
   * the credential, the request context **must not** be reused again, or you may not be able to
   * redeem a valid payment invoice.
   *
   * Note that you may in fact redeem *multiple* invoices for the same request context while
   * retrying this operation if a later invoice gets paid while you are retrying. However, the
   * returned receipt is always for the latest invoice, so it will have the latest expiration
   * possible and no entitlement time will be lost.
   *
   * Clients **must** validate that the generated receipt credential's level matches their
   * expectations. In particular, if you are currently at subscription level 100, and send a
   * request to change to level 200, you may get a receipt for level 100 or level 200 until you
   * get a successful response for the level change request. (Consider a successful level change
   * request where the connection drops before the response makes it back to the client.)
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [ReceiptCredentialException.PaymentStillProcessing]
   * indicates the most recent subscription renewal has not happened yet; retrying immediately is
   * unlikely to help, but retrying later may succeed. [ReceiptCredentialException.PaymentNotFound]
   * indicates either that the `subscriberId` is not associated with an active subscription, or that
   * the server has no record of `subscriberId` at all.
   */
  public fun getReceiptCredential(
    subscriberId: ByteArray,
    receiptCredentialRequestContext: ReceiptCredentialRequestContext,
    serverParams: ServerPublicParams,
  ): CompletableFuture<RequestResult<ReceiptCredential, ReceiptCredentialException>> =
    liftExceptions {
      NativeNice
        .UnauthenticatedChatConnection_get_subscription_receipt_credential(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          subscriberId = subscriberId,
          receiptCredentialRequestContext = receiptCredentialRequestContext,
          serverParams = serverParams,
        )
    }.mapWithCancellation(
      onSuccess = { RequestResult.Success(it) },
      onError = { err -> err.toRequestResult<ReceiptCredentialException>() },
    )
}
