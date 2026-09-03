//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation

public data class PreKeyCounts(
  /**
   * The approximate number of one-time EC pre-keys stored for the authenticated device and
   * associated with the caller's ACI.
   */
  val aciEcPreKeyCount: Int,
  /**
   * The approximate number of one-time KEM pre-keys stored for the authenticated device and
   * associated with the caller's ACI.
   */
  val aciKemPreKeyCount: Int,
  /**
   * The approximate number of one-time EC pre-keys stored for the authenticated device and
   * associated with the caller's PNI.
   */
  val pniEcPreKeyCount: Int,
  /**
   * The approximate number of one-time KEM pre-keys stored for the authenticated device and
   * associated with the caller's PNI.
   */
  val pniKemPreKeyCount: Int,
)

public class AuthKeysService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Retrieves an approximate count of the number of the various kinds of one-time pre-keys stored
   * for the authenticated device.
   *
   * On success, the resulting [PreKeyCounts] holds the number of unused one-time pre-keys the
   * server is currently storing for the authenticated device, broken down by identity (ACI or PNI)
   * and key kind (EC or KEM). Last-resort KEM pre-keys are not included in the counts. The counts
   * are approximate in that keys may be handed out to senders at any time, including while this
   * request is in flight.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun getPreKeyCount(): CompletableFuture<RequestResult<PreKeyCounts, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_get_pre_key_count(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}
