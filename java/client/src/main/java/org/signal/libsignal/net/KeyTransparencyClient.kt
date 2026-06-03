//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.keytrans.KeyTransparencyException
import org.signal.libsignal.keytrans.Store
import org.signal.libsignal.keytrans.VerificationFailedException
import org.signal.libsignal.net.KeyTransparency.CheckMode
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.ServiceId

/**
 * Typed API to access the key transparency subsystem using an existing unauthenticated chat
 * connection.
 *
 * Unlike [ChatConnection], key transparency client does not export "raw" send/receive APIs, and
 * instead uses them internally to implement high-level operations.
 *
 * All operations return [RequestResult]. Request-specific failures are represented as
 * [RequestResult.NonSuccess] with [KeyTransparencyException]; retryable network errors as
 * [RequestResult.RetryableNetworkError].
 *
 * Note: [Store] APIs may be invoked concurrently. Here are possible strategies to make sure there
 * are no thread safety violations:
 * - Types implementing [Store] can be made thread safe
 * - [KeyTransparencyClient] operations-completed asynchronous calls-can be serialized.
 *
 * Example usage:
 * ```
 * val net = Network(Network.Environment.STAGING, "key-transparency-example")
 * val chat = net.connectUnauthChat(Listener()).get()
 * chat.start()
 *
 * val client = chat.keyTransparencyClient()
 *
 * val result = client.check(CheckMode.Contact, aci, identityKey, null, null, null, KT_DATA_STORE).get()
 * ```
 */
public class KeyTransparencyClient internal constructor(
  private val chatConnection: UnauthenticatedChatConnection,
  private val tokioAsyncContext: TokioAsyncContext,
  private val environment: Network.Environment,
) {
  /**
   * A unified key transparency operation that performs a search, a monitor, or both.
   *
   * Caller should pass latest known values of all identifiers (ACI, E.164, username hash) associated
   * with the account, along with a correct value of [CheckMode].
   *
   * If there is no data in the store for the account, the search operation will be performed. Following
   * this initial search, the monitor operation will be used.
   *
   * If any of the fields in the monitor response contain a version that is higher than the one
   * currently in the store, the behavior depends on the mode parameter value.
   * - [CheckMode.Self] - A [KeyTransparencyException] will be returned, no search request will
   *   be issued.
   * - [CheckMode.Contact] - Another search request will be performed automatically and, if it succeeds,
   *   the updated account data will be stored.
   *
   * Possible non-success results include:
   * - [RequestResult.RetryableNetworkError] for errors related to communication with the server,
   *   including [RetryLaterException] when the client is being throttled,
   *   [ServerSideErrorException], [NetworkException], [NetworkProtocolException], and
   *   [TimeoutException].
   * - [RequestResult.NonSuccess] with [KeyTransparencyException] for errors related to key
   *   transparency logic, which includes missing required fields in the serialized data.
   *   Retrying without changing any of the arguments (including the state of the store) is
   *   unlikely to yield a different result.
   * - [RequestResult.NonSuccess] with [VerificationFailedException] (a subclass of
   *   [KeyTransparencyException]) indicating a failure to verify the data in key transparency
   *   server response, such as an incorrect proof or a wrong signature.
   * - [RequestResult.ApplicationError] for invalid arguments or other caller errors that could have
   *   been avoided, such as providing an [unidentifiedAccessKey] without an [e164].
   *
   * @param mode Mode of the key transparency operation being performed. See [CheckMode].
   * @param aci the ACI of the account to be checked. Required.
   * @param aciIdentityKey [IdentityKey] associated with the ACI. Required.
   * @param e164 string representation of an E.164 number associated with the account. Optional.
   * @param unidentifiedAccessKey unidentified access key for the account. This parameter has the
   *   same optionality as the E.164 parameter.
   * @param usernameHash hash of the username associated with the account. Optional.
   * @param store local persistent storage for key transparency-related data, such as the latest
   *   tree heads and account monitoring data. It will be queried for data before performing the
   *   server request and updated with the latest information from the server response if it
   *   succeeds.
   * @return an instance of [CompletableFuture] that completes with a [RequestResult] indicating
   *   success or containing the error details.
   */
  public fun check(
    mode: CheckMode,
    aci: ServiceId.Aci,
    aciIdentityKey: IdentityKey,
    e164: String?,
    unidentifiedAccessKey: ByteArray?,
    usernameHash: ByteArray?,
    store: Store,
  ): CompletableFuture<RequestResult<Unit, KeyTransparencyException>> {
    val lastDistinguishedTreeHead =
      try {
        store.lastDistinguishedTreeHead
      } catch (t: Throwable) {
        return CompletableFuture.completedFuture(RequestResult.ApplicationError(t))
      }

    return try {
      NativeHandleGuard(tokioAsyncContext).use { tokioContextGuard ->
        NativeHandleGuard(aciIdentityKey.publicKey).use { identityKeyGuard ->
          NativeHandleGuard(chatConnection).use { chatConnectionGuard ->
            Native
              .KeyTransparency_Check(
                tokioContextGuard.nativeHandle(),
                environment.value,
                chatConnectionGuard.nativeHandle(),
                aci.toServiceIdFixedWidthBinary(),
                identityKeyGuard.nativeHandle(),
                e164,
                unidentifiedAccessKey,
                usernameHash,
                // Technically this is a required parameter, but passing null
                // to generate the error on the Rust side.
                store.getAccountData(aci).orElse(null),
                lastDistinguishedTreeHead.orElse(null),
                mode.isSelf(),
                mode.isE164Discoverable() ?: true,
              ).mapWithCancellation(
                onSuccess = { (updatedAccountData, distinguished) ->
                  try {
                    store.setAccountData(aci, updatedAccountData)
                    if (distinguished.isNotEmpty()) {
                      store.setLastDistinguishedTreeHead(distinguished)
                    }
                    RequestResult.Success(Unit)
                  } catch (t: Throwable) {
                    RequestResult.ApplicationError(t)
                  }
                },
                onError = { err -> err.toRequestResult<KeyTransparencyException>() },
              )
          }
        }
      }
    } catch (t: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(t))
    }
  }
}
