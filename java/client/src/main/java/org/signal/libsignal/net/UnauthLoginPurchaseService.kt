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
import java.time.Instant

@Deprecated(message = "renamed to ReceiptCredentialException", replaceWith = ReplaceWith("ReceiptCredentialException"))
public typealias CreateLoginReceiptCredentialException = ReceiptCredentialException

public sealed class LoginReceiptLevel {
  public data object Normal : LoginReceiptLevel()

  public data object Sandbox : LoginReceiptLevel()
}

public class UnauthLoginPurchaseService(
  private val connection: UnauthenticatedChatConnection,
) {
  /**
   * Obtain a ZK receipt credential for a completed one-time login payment.
   * The receipt credential can then be presented at registration.
   *
   * Subsequent retries to create a login credential for the same `purchaseIdentifier` must use
   * an identical `receiptCredentialRequestContext`.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [ReceiptCredentialException.PaymentStillProcessing] error
   * should be rare if payment has already been confirmed locally, but the client may retry the
   * request. [ReceiptCredentialException.PaymentNotFound] indicates that the server has no record
   * of `purchaseIdentifier`, which may be a client issue, a server issue, or a problem with the
   * payment processor; it is not worth retrying.
   */
  public fun createLoginReceiptCredential(
    paymentProcessor: PaymentProvider,
    purchaseIdentifier: String,
    receiptCredentialRequestContext: ReceiptCredentialRequestContext,
    serverParams: ServerPublicParams,
    purchaseTime: Instant,
    expectedLevel: LoginReceiptLevel,
  ): CompletableFuture<RequestResult<ReceiptCredential, ReceiptCredentialException>> =
    liftExceptions {
      NativeNice
        .UnauthenticatedChatConnection_create_login_receipt_credential(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          paymentProcessor = paymentProcessor,
          purchaseIdentifier = purchaseIdentifier,
          receiptCredentialRequestContext = receiptCredentialRequestContext,
          serverParams = serverParams,
          purchaseTime = purchaseTime,
          expectedLevel = expectedLevel,
        )
    }.mapWithCancellation(
      onSuccess = { RequestResult.Success(it) },
      onError = { err -> err.toRequestResult<ReceiptCredentialException>() },
    )
}
