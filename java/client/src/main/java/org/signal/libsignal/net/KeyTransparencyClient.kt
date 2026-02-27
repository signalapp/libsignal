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
import org.signal.libsignal.net.KeyTransparency.MonitorMode
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
 * val result = client.search(aci, identityKey, null, null, null, KT_DATA_STORE).get()
 * ```
 */
public class KeyTransparencyClient internal constructor(
  private val chatConnection: UnauthenticatedChatConnection,
  private val tokioAsyncContext: TokioAsyncContext,
  private val environment: Network.Environment,
) {
  /**
   * Search for account information in the key transparency tree.
   *
   * Only ACI and ACI identity key are required to identify the account.
   *
   * If the latest distinguished tree head is not present in the store, it will be requested from
   * the server prior to performing the search via [updateDistinguished].
   *
   * Possible non-success results include:
   * - [RequestResult.RetryableNetworkError] for errors related to communication with the server,
   *   including [RetryLaterException] when the client is being throttled,
   *   [ServerSideErrorException], [NetworkException], [NetworkProtocolException], and
   *   [TimeoutException].
   * - [RequestResult.NonSuccess] with [KeyTransparencyException] for errors related to key
   *   transparency logic, which includes missing required fields in the serialized data.
   *   Retrying the search without changing any of the arguments (including the state of the
   *   store) is unlikely to yield a different result.
   * - [RequestResult.NonSuccess] with [VerificationFailedException] (a subclass of
   *   [KeyTransparencyException]) indicating a failure to verify the data in key transparency
   *   server response, such as an incorrect proof or a wrong signature.
   * - [RequestResult.ApplicationError] for invalid arguments or other caller errors that could have
   *   been avoided, such as providing an [unidentifiedAccessKey] without an [e164].
   *
   * @param aci the ACI of the account to be searched for. Required.
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
  public fun search(
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

    if (lastDistinguishedTreeHead.isEmpty) {
      return updateDistinguished(store).thenCompose { result ->
        when (result) {
          is RequestResult.Success ->
            search(aci, aciIdentityKey, e164, unidentifiedAccessKey, usernameHash, store)
          else -> CompletableFuture.completedFuture(result)
        }
      }
    }

    return try {
      NativeHandleGuard(tokioAsyncContext).use { tokioContextGuard ->
        NativeHandleGuard(aciIdentityKey.publicKey).use { identityKeyGuard ->
          NativeHandleGuard(chatConnection).use { chatConnectionGuard ->
            Native
              .KeyTransparency_Search(
                tokioContextGuard.nativeHandle(),
                environment.value,
                chatConnectionGuard.nativeHandle(),
                aci.toServiceIdFixedWidthBinary(),
                identityKeyGuard.nativeHandle(),
                e164,
                unidentifiedAccessKey,
                usernameHash,
                store.getAccountData(aci).orElse(null),
                lastDistinguishedTreeHead.get(),
              ).mapWithCancellation(
                onSuccess = { accountData ->
                  try {
                    store.setAccountData(aci, accountData)
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

  /**
   * Request the latest distinguished tree head from the server and update it in the local store.
   *
   * Possible non-success results include:
   * - [RequestResult.RetryableNetworkError] for errors related to communication with the server,
   *   including [RetryLaterException] when the client is being throttled,
   *   [ServerSideErrorException], [NetworkException], [NetworkProtocolException], and
   *   [TimeoutException].
   * - [RequestResult.NonSuccess] with [KeyTransparencyException] for errors related to key
   *   transparency logic. Retrying without changing any of the arguments (including the state of
   *   the store) is unlikely to yield a different result.
   * - [RequestResult.NonSuccess] with [VerificationFailedException] (a subclass of
   *   [KeyTransparencyException]) indicating a failure to verify the data in key transparency
   *   server response, such as an incorrect proof or a wrong signature.
   * - [RequestResult.ApplicationError] for invalid arguments or other caller errors that could have
   *   been avoided.
   *
   * @param store local persistent storage for key transparency related data, such as the latest
   *   tree heads and account monitoring data. It will be queried for the latest distinguished tree
   *   head before performing the server request and updated with data from the server response if
   *   it succeeds. Distinguished tree does not have to be present in the store prior to the call.
   * @return an instance of [CompletableFuture] that completes with a [RequestResult] indicating
   *   success or containing the error details.
   */
  public fun updateDistinguished(store: Store): CompletableFuture<RequestResult<Unit, KeyTransparencyException>> {
    val lastDistinguished =
      try {
        store.lastDistinguishedTreeHead.orElse(null)
      } catch (t: Throwable) {
        return CompletableFuture.completedFuture(RequestResult.ApplicationError(t))
      }

    return try {
      NativeHandleGuard(tokioAsyncContext).use { tokioContextGuard ->
        NativeHandleGuard(chatConnection).use { chatConnectionGuard ->
          Native
            .KeyTransparency_Distinguished(
              tokioContextGuard.nativeHandle(),
              environment.value,
              chatConnectionGuard.nativeHandle(),
              lastDistinguished,
            ).mapWithCancellation(
              onSuccess = { distinguished ->
                try {
                  store.setLastDistinguishedTreeHead(distinguished)
                  RequestResult.Success(Unit)
                } catch (t: Throwable) {
                  RequestResult.ApplicationError(t)
                }
              },
              onError = { err -> err.toRequestResult<KeyTransparencyException>() },
            )
        }
      }
    } catch (t: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(t))
    }
  }

  /**
   * Issue a monitor request to the key transparency service.
   *
   * Store must contain data associated with the account being requested prior to making this call.
   * Another way of putting this is: monitor cannot be called before [search].
   *
   * If any of the monitored fields in the server response contain a version that is higher than
   * the one currently in the store, the behavior depends on the mode parameter value.
   * - [MonitorMode.SELF] - A [KeyTransparencyException] will be returned, no search request will
   *   be issued.
   * - [MonitorMode.OTHER] - A search request will be performed automatically and, if it succeeds,
   *   the updated account data will be stored.
   *
   * If the latest distinguished tree head is not present in the store, it will be requested from
   * the server prior to performing the monitor via [updateDistinguished].
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
   * @param mode Mode of the monitor operation. See [MonitorMode].
   * @param aci the ACI of the account to be searched for. Required.
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
  public fun monitor(
    mode: MonitorMode,
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

    if (lastDistinguishedTreeHead.isEmpty) {
      return updateDistinguished(store).thenCompose { result ->
        when (result) {
          is RequestResult.Success ->
            monitor(mode, aci, aciIdentityKey, e164, unidentifiedAccessKey, usernameHash, store)
          else -> CompletableFuture.completedFuture(result)
        }
      }
    }

    return try {
      NativeHandleGuard(tokioAsyncContext).use { tokioContextGuard ->
        NativeHandleGuard(aciIdentityKey.publicKey).use { identityKeyGuard ->
          NativeHandleGuard(chatConnection).use { chatConnectionGuard ->
            Native
              .KeyTransparency_Monitor(
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
                lastDistinguishedTreeHead.get(),
                mode == MonitorMode.SELF,
              ).mapWithCancellation(
                onSuccess = { updatedAccountData ->
                  try {
                    store.setAccountData(aci, updatedAccountData)
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
