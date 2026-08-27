//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialPresentation

public class AuthBackupsService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Redeem a receipt to mark the account as eligible for the paid backup tier.
   *
   * After successful redemption, fetched BackupAuthCredentials will include the level on the
   * provided receipt until the expiration time on the receipt.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. An [InvalidReceiptException] indicates the receipt was
   * invalid or expired; a [MissingBackupIdException] indicates there is no backup ID on the
   * account.
   */
  public fun redeemReceipt(
    presentation: ReceiptCredentialPresentation,
  ): CompletableFuture<RequestResult<Unit, RedeemBackupReceiptFailure>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_redeem_backup_receipt(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          presentation = presentation,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult<RedeemBackupReceiptFailure>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}

/** Either [InvalidReceiptException] or [MissingBackupIdException]. */
public sealed interface RedeemBackupReceiptFailure : BadRequestError
