//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.CurrencyConversionsInternal
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation

public data class CurrencyConversions(
  public val timestamp: java.time.Instant,
  public val currencies: List<Currency>,
)

public data class Currency(
  public val base: String,
  /**
   * The values of this map are decimal conversion rates.
   */
  public val conversions: Map<String, String>,
)

// Public for testing
public fun CurrencyConversionsInternal.toPublic(): CurrencyConversions =
  CurrencyConversions(
    timestamp = this.timestampMs,
    currencies =
      this.currencies.map {
        Currency(
          base = it.base,
          conversions = it.conversions.toMap(),
        )
      },
  )

public class AuthPaymentsService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Return the current currency conversion rates.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun getCurrencyConversions(): CompletableFuture<RequestResult<CurrencyConversions, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_get_currency_conversions(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
        ).mapWithCancellation(
          onSuccess = {
            RequestResult.Success(
              it.toPublic(),
            )
          },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}
