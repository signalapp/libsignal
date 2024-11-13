//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.signal.libsignal.net.KeyTransparency.searchKeyForAci;

import java.util.Optional;
import java.util.function.Function;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.keytrans.SearchContext;
import org.signal.libsignal.keytrans.SearchResult;
import org.signal.libsignal.keytrans.Store;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ServiceId;

/**
 * Typed API to access the key transparency subsystem using an existing unauthenticated chat
 * connection.
 *
 * <p>Unlike {@link ChatService}, key transparency client does not export "raw" send/receive APIs,
 * and instead uses them internally to implement high-level operations.
 */
public class KeyTransparencyClient {
  private final TokioAsyncContext tokioAsyncContext;
  private final UnauthenticatedChatService chat;

  KeyTransparencyClient(UnauthenticatedChatService chat, TokioAsyncContext tokioAsyncContext) {
    this.chat = chat;
    this.tokioAsyncContext = tokioAsyncContext;
  }

  /**
   * Search for account information in the key transparency tree.
   *
   * <p>Only ACI and ACI identity key are required to identify the account.
   *
   * <p>If the latest distinguished tree head is not present in the store, it will be requested from
   * the server prior to performing the search via {@link #updateDistinguished}.
   *
   * <p>This is an asynchronous operation; all the exceptions occurring during communication with
   * the server will be wrapped in {@link java.util.concurrent.ExecutionException}.
   *
   * <p>Possible exceptions include:
   *
   * <ul>
   *   <li>{@link ChatServiceException} for errors related to communication with the server.
   *       Depending on the severity, the search can be retried.
   *   <li>{@link KeyTransparencyException} for errors related to key transparency logic. Retrying
   *       the search without changing any of the arguments (including the state of the store) is
   *       unlikely to yield a different result.
   * </ul>
   *
   * @param aci the ACI of the account to be searched for. Required.
   * @param aciIdentityKey {@link IdentityKey} associated with the ACI. Required. Although key
   *     transparency is used to request this information, passing it in the request lets chat
   *     server know that it is not a random guess and that the caller of this API has communicated
   *     with the ACI.
   * @param e164 string representation of an E.164 number associated with the account. Optional.
   * @param unidentifiedAccessKey provides the same guess protections as the ACI identity key. This
   *     parameter has the same optionality as the E.164 parameter.
   * @param usernameHash hash of the username associated with the account. Optional.
   * @param store local persistent storage for key transparency-related data, such as the latest
   *     tree heads and account monitoring data. It will be queried for data before performing the
   *     server request and updated with the latest information from the server response if it
   *     succeeds.
   * @return an instance of {@link CompletableFuture} that, upon success, will return {@link
   *     SearchResult} containing the requested information and will update the latest tree head and
   *     account monitoring data in the store.
   * @throws IllegalArgumentException if the store contains corrupted data.
   */
  public CompletableFuture<SearchResult> search(
      /* @NotNull */ final ServiceId.Aci aci,
      /* @NotNull */ final IdentityKey aciIdentityKey,
      final String e164,
      final byte[] unidentifiedAccessKey,
      final byte[] usernameHash,
      final Store store) {
    Optional<byte[]> lastDistinguishedTreeHead = store.getLastDistinguishedTreeHead();
    if (lastDistinguishedTreeHead.isEmpty()) {
      return this.updateDistinguished(store)
          .thenCompose(
              (ignored) ->
                  this.search(
                      aci, aciIdentityKey, e164, unidentifiedAccessKey, usernameHash, store));
    }
    byte[] e164SearchKey = mapNullable(e164, KeyTransparency::searchKeyForE164);
    byte[] usernameHashSearchKey =
        mapNullable(usernameHash, KeyTransparency::searchKeyForUsernameHash);
    SearchContext searchContext;
    // Decoding of the last distinguished tree head happens "eagerly" while constructing the
    // SearchContext. It may result in an IllegalArgumentError.
    searchContext =
        SearchContext.builder()
            .withLastTreeHead(store.getLastTreeHead().orElse(null))
            .withAciMonitor(store.getMonitorData(searchKeyForAci(aci)).orElse(null))
            .withE164Monitor(store.getMonitorData(e164SearchKey).orElse(null))
            .withUsernameHashMonitor(store.getMonitorData(usernameHashSearchKey).orElse(null))
            .withLastDistinguishedTreeHead(lastDistinguishedTreeHead.get())
            .build();
    try (NativeHandleGuard tokioContextGuard = this.tokioAsyncContext.guard();
        NativeHandleGuard chatGuard = chat.guard();
        NativeHandleGuard identityKeyGuard = aciIdentityKey.getPublicKey().guard();
        NativeHandleGuard searchContextGuard = searchContext.guard()) {
      return Native.KeyTransparency_Search(
              tokioContextGuard.nativeHandle(),
              chat.environment.value,
              chatGuard.nativeHandle(),
              aci.toServiceIdFixedWidthBinary(),
              identityKeyGuard.nativeHandle(),
              e164,
              unidentifiedAccessKey,
              usernameHash,
              searchContextGuard.nativeHandle())
          .thenApply(
              (handle) -> {
                SearchResult result = new SearchResult(handle);
                store.applyUpdates(result);
                return result;
              });
    }
  }

  /**
   * Request the latest distinguished tree head from the server and update it in the local store.
   *
   * <p>This is an asynchronous operation; all the exceptions occurring during communication with
   * the server will be wrapped in {@link java.util.concurrent.ExecutionException}.
   *
   * <p>Possible exceptions include:
   *
   * <ul>
   *   <li>{@link ChatServiceException} for errors related to communication with the server.
   *       Depending on the severity, the request can be retried.
   *   <li>{@link KeyTransparencyException} for the errors related to key transparency logic.
   *       Retrying the search without changing any of the arguments (including the state of the
   *       store) is unlikely to produce a different result.
   * </ul>
   *
   * @param store local persistent storage for key transparency related data, such as the latest
   *     tree heads and account monitoring data. It will be queried for the latest distinguished
   *     tree head before performing the server request and updated with data from the server
   *     response if it succeeds. Distinguished tree does not have to be present in the store prior
   *     to the call.
   * @return An instance of {@link CompletableFuture} representing the asynchronous operation, which
   *     does not produce any value. Successful completion of the operation results in an updated
   *     state of the store.
   * @throws IllegalArgumentException if the store contains corrupted data.
   */
  public CompletableFuture<Void> updateDistinguished(final Store store) {
    byte[] lastDistinguished = store.getLastDistinguishedTreeHead().orElse(null);
    try (NativeHandleGuard tokioContextGuard = this.tokioAsyncContext.guard();
        NativeHandleGuard chatGuard = chat.guard()) {
      return Native.KeyTransparency_Distinguished(
              tokioContextGuard.nativeHandle(),
              chat.environment.value,
              chatGuard.nativeHandle(),
              lastDistinguished)
          .thenApply(
              bytes -> {
                store.setLastDistinguishedTreeHead(bytes);
                return null;
              });
    }
  }

  private static <T, U> U mapNullable(T what, Function<? super T, ? extends U> mapper) {
    if (what == null) {
      return null;
    }
    return mapper.apply(what);
  }
}
