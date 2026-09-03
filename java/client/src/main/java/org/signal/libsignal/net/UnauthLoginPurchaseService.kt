//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.signal.libsignal.zkgroup.receipts.ReceiptCredential
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialRequestContext
import java.io.IOException
import java.time.Instant

public sealed class PaymentProvider {
  public data object GooglePlayBilling : PaymentProvider()

  public data object AppleAppStore : PaymentProvider()

  public data object Stripe : PaymentProvider()

  public data object Braintree : PaymentProvider()
}

public data class ChargeFailure(
  public val processor: PaymentProvider,
  public val code: String,
  public val message: String,
  public val outcomeNetworkStatus: String?,
  public val outcomeReason: String?,
  public val outcomeType: String?,
)

public sealed class CreateLoginReceiptCredentialException(
  message: String,
) : IOException(message),
  BadRequestError {
  /**
   * The purchase is still pending with the payment provider. The client may retry later.
   */
  public class PaymentStillProcessing : CreateLoginReceiptCredentialException {
    @CalledFromNative
    public constructor(message: String) : super(message)
  }

  /**
   * The purchase did not complete successfully.
   */
  public class PaymentRequired : CreateLoginReceiptCredentialException {
    public val chargeFailure: ChargeFailure?

    @CalledFromNative
    public constructor(message: String, chargeFailure: ChargeFailure?) : super(message) {
      this.chargeFailure = chargeFailure
    }
  }

  /**
   * The payment provider has no purchase with the provided purchase_identifier
   */
  public class PaymentNotFound : CreateLoginReceiptCredentialException {
    @CalledFromNative
    public constructor(message: String) : super(message)
  }

  /**
   * The purchase was already redeemed for a receipt credential, but with a different receipt
   * credential request
   */
  public class ReceiptAlreadyIssued : CreateLoginReceiptCredentialException {
    @CalledFromNative
    public constructor(message: String) : super(message)
  }
}

public class UnauthLoginPurchaseService(
  private val connection: UnauthenticatedChatConnection,
) {
  /**
   * Obtain a ZK receipt credential for a completed one-time login payment.
   * The receipt credential can then be presented at registration.
   *
   * Subsequent retries to create a login credential for the same purchaseIdentifier must use
   * an identical receiptCredentialRequestContext.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun createLoginReceiptCredential(
    paymentProcessor: PaymentProvider,
    purchaseIdentifier: String,
    receiptCredentialRequestContext: ReceiptCredentialRequestContext,
    serverParams: ServerPublicParams,
    purchaseTime: Instant,
  ): CompletableFuture<RequestResult<ReceiptCredential, CreateLoginReceiptCredentialException>> =
    try {
      NativeNice
        .UnauthenticatedChatConnection_create_login_receipt_credential(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          paymentProcessor = paymentProcessor,
          purchaseIdentifier = purchaseIdentifier,
          receiptCredentialRequestContext = receiptCredentialRequestContext,
          serverParams = serverParams,
          purchaseTime = purchaseTime,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err -> err.toRequestResult<CreateLoginReceiptCredentialException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}
