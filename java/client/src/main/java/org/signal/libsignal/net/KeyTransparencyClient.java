//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.util.Optional;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.internal.TokioAsyncContext;
import org.signal.libsignal.keytrans.Store;
import org.signal.libsignal.net.KeyTransparency.MonitorMode;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ServiceId;

/**
 * Typed API to access the key transparency subsystem using an existing unauthenticated chat
 * connection.
 *
 * <p>Unlike {@link ChatConnection}, key transparency client does not export "raw" send/receive
 * APIs, and instead uses them internally to implement high-level operations.
 *
 * <p>Note: {@code Store} APIs may be invoked concurrently. Here are possible strategies to make
 * sure there are no thread safety violations:
 *
 * <ul>
 *   <li>Types implementing {@code Store} can be made thread safe
 *   <li>{@link KeyTransparencyClient} operations-completed asynchronous calls-can be serialized.
 * </ul>
 *
 * <p>Example usage:
 *
 * <pre>
 * var net = new Network(Network.Environment.STAGING, "key-transparency-example");
 * var chat = net.connectUnauthChat(new Listener()).get();
 * chat.start();
 *
 * KeyTransparencyClient client = chat.keyTransparencyClient();
 *
 * client.search(aci, identityKey, null, null, null, KT_DATA_STORE).get();
 *
 * </pre>
 */
public class KeyTransparencyClient {
  private final TokioAsyncContext tokioAsyncContext;
  private final UnauthenticatedChatConnection chatConnection;
  private final Network.Environment environment;

  KeyTransparencyClient(
      UnauthenticatedChatConnection chat,
      TokioAsyncContext tokioAsyncContext,
      Network.Environment environment) {
    this.chatConnection = chat;
    this.tokioAsyncContext = tokioAsyncContext;
    this.environment = environment;
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
   *       Depending on the concrete subclass, client can retry the operation. See also {@link
   *       TimeoutException}, {@link ServerSideErrorException}, {@link UnexpectedResponseException},
   *       {@link AppExpiredException},
   *   <li>{@link RetryLaterException} when the client is being throttled. Wait for the specified
   *       amount of time before making new requests.
   *   <li>{@link NetworkException} when the network operation fails. Clients can retry the call
   *       after a recommended period.
   *   <li>{@link NetworkProtocolException} when a high level network protocol fails. For example,
   *       failure to establish a websocket connection.
   *   <li>{@link org.signal.libsignal.keytrans.KeyTransparencyException} for errors related to key
   *       transparency logic, which includes missing required fields in the serialized data.
   *       Retrying the search without changing any of the arguments (including the state of the
   *       store) is unlikely to yield a different result.
   *   <li>{@link org.signal.libsignal.keytrans.VerificationFailedException} indicates a failure to
   *       verify the data in key transparency server response, such as an incorrect proof or a
   *       wrong signature.
   * </ul>
   *
   * @param aci the ACI of the account to be searched for. Required.
   * @param aciIdentityKey {@link IdentityKey} associated with the ACI. Required.
   * @param e164 string representation of an E.164 number associated with the account. Optional.
   * @param unidentifiedAccessKey unidentified access key for the account. This parameter has the
   *     same optionality as the E.164 parameter.
   * @param usernameHash hash of the username associated with the account. Optional.
   * @param store local persistent storage for key transparency-related data, such as the latest
   *     tree heads and account monitoring data. It will be queried for data before performing the
   *     server request and updated with the latest information from the server response if it
   *     succeeds.
   * @return an instance of {@link CompletableFuture} successful completion of which will indicate
   *     that the search request has succeeded and store has been updated with the latest account
   *     data.
   * @throws IllegalArgumentException if the store contains corrupted data.
   */
  public CompletableFuture<Void> search(
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
    // Decoding of the last distinguished tree head happens "eagerly" before making any network
    // requests.
    // It may result in an IllegalArgumentException.
    try (NativeHandleGuard tokioContextGuard = this.tokioAsyncContext.guard();
        NativeHandleGuard identityKeyGuard = aciIdentityKey.getPublicKey().guard();
        NativeHandleGuard chatConnectionGuard = new NativeHandleGuard(chatConnection); ) {
      return Native.KeyTransparency_Search(
              tokioContextGuard.nativeHandle(),
              this.environment.value,
              chatConnectionGuard.nativeHandle(),
              aci.toServiceIdFixedWidthBinary(),
              identityKeyGuard.nativeHandle(),
              e164,
              unidentifiedAccessKey,
              usernameHash,
              store.getAccountData(aci).orElse(null),
              lastDistinguishedTreeHead.get())
          .thenApply(
              (accountData) -> {
                store.setAccountData(aci, accountData);
                return null;
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
   *       Depending on the concrete subclass, client can retry the operation. See also {@link
   *       TimeoutException}, {@link ServerSideErrorException}, {@link UnexpectedResponseException},
   *       {@link AppExpiredException},
   *   <li>{@link RetryLaterException} when the client is being throttled. Wait for the specified
   *       amount of time before making new requests.
   *   <li>{@link NetworkException} when the network operation fails. Clients can retry the call
   *       after a recommended period.
   *   <li>{@link NetworkProtocolException} when a high level network protocol fails. For example,
   *       failure to establish a websocket connection.
   *   <li>{@link org.signal.libsignal.keytrans.KeyTransparencyException} for errors related to key
   *       transparency logic. Retrying the search without changing any of the arguments (including
   *       the state of the store) is unlikely to yield a different result.
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
        NativeHandleGuard chatConnectionGuard = new NativeHandleGuard(chatConnection)) {
      return Native.KeyTransparency_Distinguished(
              tokioContextGuard.nativeHandle(),
              this.environment.value,
              chatConnectionGuard.nativeHandle(),
              lastDistinguished)
          .thenApply(
              bytes -> {
                store.setLastDistinguishedTreeHead(bytes);
                return null;
              });
    }
  }

  /**
   * Issue a monitor request to the key transparency service.
   *
   * <p>Store must contain data associated with the account being requested prior to making this
   * call. Another way of putting this is: monitor cannot be called before {@link #search}.
   *
   * <p>If any of the monitored fields in the server response contain a version that is higher than
   * the one currently in the store, the behavior depends on the mode parameter value.
   *
   * <ul>
   *   <li>{@code MonitorMode.SELF} - An exception will be thrown, no search request will be issued.
   *   <li>{@code MonitorMode.OTHER} - A search request will be performed automatically and, if it
   *       succeeds, the updated account data will be stored.
   * </ul>
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
   *       Depending on the concrete subclass, client can retry the operation. See also {@link
   *       TimeoutException}, {@link ServerSideErrorException}, {@link UnexpectedResponseException},
   *       {@link AppExpiredException},
   *   <li>{@link RetryLaterException} when the client is being throttled. Wait for the specified
   *       amount of time before making new requests.
   *   <li>{@link NetworkException} when the network operation fails. Clients can retry the call
   *       after a recommended period.
   *   <li>{@link NetworkProtocolException} when a high level network protocol fails. For example,
   *       failure to establish a websocket connection.
   *   <li>{@link org.signal.libsignal.keytrans.KeyTransparencyException} for errors related to key
   *       transparency logic, which includes missing required fields in the serialized data.
   *       Retrying the search without changing any of the arguments (including the state of the
   *       store) is unlikely to yield a different result.
   *   <li>{@link org.signal.libsignal.keytrans.VerificationFailedException} indicates a failure to
   *       verify the data in key transparency server response, such as an incorrect proof or a
   *       wrong signature.
   * </ul>
   *
   * @param mode Mode of the monitor operation. See {@link MonitorMode}.
   * @param aci the ACI of the account to be searched for. Required.
   * @param aciIdentityKey {@link IdentityKey} associated with the ACI. Required.
   * @param e164 string representation of an E.164 number associated with the account. Optional.
   * @param unidentifiedAccessKey unidentified access key for the account. This parameter has the
   *     same optionality as the E.164 parameter.
   * @param usernameHash hash of the username associated with the account. Optional.
   * @param store local persistent storage for key transparency-related data, such as the latest
   *     tree heads and account monitoring data. It will be queried for data before performing the
   *     server request and updated with the latest information from the server response if it
   *     succeeds.
   * @return an instance of {@link CompletableFuture} successful completion of which will indicate
   *     that the monitor request has succeeded and store has been updated with the latest account
   *     data.
   * @throws IllegalArgumentException if the store contains corrupted data.
   */
  public CompletableFuture<Void> monitor(
      /* @NotNull */ final MonitorMode mode,
      final ServiceId.Aci aci,
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
                  this.monitor(
                      mode, aci, aciIdentityKey, e164, unidentifiedAccessKey, usernameHash, store));
    }
    try (NativeHandleGuard tokioContextGuard = this.tokioAsyncContext.guard();
        NativeHandleGuard identityKeyGuard = aciIdentityKey.getPublicKey().guard();
        NativeHandleGuard chatConnectionGuard = new NativeHandleGuard(chatConnection)) {
      return Native.KeyTransparency_Monitor(
              tokioContextGuard.nativeHandle(),
              this.environment.value,
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
              mode == MonitorMode.SELF)
          .thenApply(
              (updatedAccountData) -> {
                store.setAccountData(aci, updatedAccountData);
                return null;
              });
    }
  }
}
