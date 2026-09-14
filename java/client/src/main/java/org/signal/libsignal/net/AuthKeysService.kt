//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.state.PreKeyRecord

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

/**
 * A one-time elliptic-curve pre-key, as uploaded to the server.
 *
 * This is only the public half of the key; the private half never leaves the device.
 */
public data class PublicEcPreKey(
  /**
   * A locally-unique identifier for this key, which peers using this key to encrypt messages will
   * provide so the private key can be looked up.
   *
   * Must not be negative.
   */
  public val keyId: Int,
  /**
   * The public key.
   */
  public val publicKey: ECPublicKey,
) {
  public constructor(record: PreKeyRecord) : this(record.id, record.keyPair.publicKey)
}

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

  /**
   * Uploads a new set of one-time EC pre-keys for the authenticated device, clearing any
   * previously-stored one-time EC pre-keys for [identity].
   *
   * @param preKeys Must contain between 1 and 100 keys
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun setOneTimeEcPreKeys(
    identity: ServiceId.Kind,
    preKeys: List<PublicEcPreKey>,
  ): CompletableFuture<RequestResult<Unit, Nothing>> {
    val ids = IntArray(preKeys.size)
    val keys = ArrayList<ECPublicKey>(preKeys.size)
    preKeys.forEachIndexed { i, next ->
      ids[i] = next.keyId
      keys.add(next.publicKey)
    }
    return try {
      NativeNice
        .AuthenticatedChatConnection_set_one_time_ec_pre_keys(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          identityType = identity,
          preKeyIds = ids,
          preKeyData = keys,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
  }
}
