//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

/**
 * This class provides functionality for communicating with SVR3
 *
 * <p>Its instance can be obtained from an {@link org.signal.libsignal.net.Network#svr3()} property
 * of the {@link org.signal.libsignal.net.Network} class.
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * // Obtain a Network instance
 * Network net = new Network(Network.Environment.STAGING);
 * // Instantiate EnclaveAuth with the username and password obtained from the Chat Server.
 * EnclaveAuth auth = new EnclaveAuth(USERNAME, ENCLAVE_PASSWORD);
 * // Store a value in SVR3. Here 10 is the number of permitted restore attempts.
 * byte[] shareSet = net.svr3().backup(SECRET_TO_BE_STORED, PASSWORD, 10, auth).get();
 * byte[] restoredSecret = net.svr3().restore(PASSWORD, shareSet, auth).get();
 * }</pre>
 *
 * <p>Please note that the methods of this class return {@link
 * org.signal.libsignal.internal.CompletableFuture}s and do not throw any exceptions themselves. The
 * actual exceptions will be thrown only when the Futures' results are awaited and are wrapped in
 * {@link java.util.concurrent.ExecutionException}, so the {@link
 * java.util.concurrent.ExecutionException#getCause()} needs to be used to recover the underlying
 * exception instance.
 */
public final class Svr3 {
  private Network network;

  Svr3(Network network) {
    this.network = network;
  }

  /**
   * Backup a secret to SVR3.
   *
   * <p>As noted above due to the asynchronous nature of the API all the expected errors will only
   * be thrown when the Future is awaited, and furthermore will be wrapped in {@link
   * java.util.concurrent.ExecutionException}.
   *
   * <p>Exception messages are expected to be log-safe and not contain any sensitive data.
   *
   * @param what the secret to be stored. Must be 32 bytes long.
   * @param password user-provide password that will be used to derive the encryption key for the
   *     secret.
   * @param maxTries number of times the secret will be allowed to be guessed. Each call to {@link
   *     #restore} that has reached the server will decrement the counter. Must be positive.
   * @param auth an instance of {@link org.signal.libsignal.net.EnclaveAuth} containing the username
   *     and password obtained from the Chat Server. The password is an OTP which is generally good
   *     for about 15 minutes, therefore it can be reused for the subsequent calls to either backup
   *     or restore that are not too far apart in time.
   * @return an instance of {@link org.signal.libsignal.internal.CompletableFuture} which-when
   *     awaited-will return a byte array with a serialized masked share set. It is supposed to be
   *     an opaque blob for the clients and therefore no assumptions should be made about its
   *     contents. This byte array should be stored by the clients and used to restore the secret
   *     along with the password. Please note that masked share set does not have to be treated as
   *     secret.
   * @throws {@link org.signal.libsignal.net.NetworkException} in case of network related errors,
   *     including connect timeout and failed auth.
   * @throws {@link org.signal.libsignal.attest.AttestationFailedException} when an attempt to
   *     validate the server attestation document fails.
   * @throws {@link org.signal.libsignal.sgxsession.SgxCommunicationFailureException} when a Noise
   *     connection error happens.
   */
  public final CompletableFuture<byte[]> backup(
      byte[] what, String password, int maxTries, EnclaveAuth auth) {
    try (NativeHandleGuard asyncRuntime = new NativeHandleGuard(this.network.getAsyncContext());
        NativeHandleGuard connectionManager =
            new NativeHandleGuard(this.network.getConnectionManager())) {

      return Native.Svr3Backup(
          asyncRuntime.nativeHandle(),
          connectionManager.nativeHandle(),
          what,
          password,
          maxTries,
          auth.username,
          auth.password);
    }
  }

  /**
   * Restore a secret from SVR3.
   *
   * <p>As noted above due to the asynchronous nature of the API all the expected errors will only
   * be thrown when the Future is awaited, and furthermore will be wrapped in {@link
   * java.util.concurrent.ExecutionException}.
   *
   * <p>Exception messages are expected to be log-safe and not contain any sensitive data.
   *
   * <p>Note on exceptions. Only the operations resulting in {@link
   * org.signal.libsignal.net.NetworkException} should be retried (even though there are multiple
   * layers of retries with back-off built in). Other exceptions are caused by the bad input or data
   * missing on the server. They are therefore non-actionable and are guaranteed to be thrown again
   * when retried.
   *
   * @param password user-provide password that will be used to derive the decryption key for the
   *     secret.
   * @param shareSet a serialized masked share set returned by a call to {@link #backup}.
   * @param auth an instance of {@link org.signal.libsignal.net.EnclaveAuth} containing the username
   *     and password obtained from the Chat Server. The password is an OTP which is generally good
   *     for about 15 minutes, therefore it can be reused for the subsequent calls to either backup
   *     or restore that are not too far apart in time.
   * @return an instance of {@link org.signal.libsignal.internal.CompletableFuture} which-when
   *     awaited-will return a byte array with the restored secret.
   * @throws {@link org.signal.libsignal.net.NetworkException} in case of network related errors,
   *     including connection timeouts and failed auth.
   * @throws {@link org.signal.libsignal.svr.DataMissingException} when the maximum restore attempts
   *     number has been exceeded or if the value has never been backed up.
   * @throws {@link org.signal.libsignal.svr.RestoreFailedException} when the combination of the
   *     password and masked share set does not result in successful restoration of the secret.
   * @throws {@link org.signal.libsignal.svr.SvrException} when the de-serialization of a masked
   *     share set fails, or when the server requests fail for reasons other than "maximum attempts
   *     exceeded".
   * @throws {@link org.signal.libsignal.attest.AttestationFailedException} when an attempt to
   *     validate the server attestation document fails.
   * @throws {@link org.signal.libsignal.sgxsession.SgxCommunicationFailureException} when a Noise
   *     connection error happens.
   */
  public final CompletableFuture<byte[]> restore(
      String password, byte[] shareSet, EnclaveAuth auth) {
    try (NativeHandleGuard asyncRuntime = new NativeHandleGuard(this.network.getAsyncContext());
        NativeHandleGuard connectionManager =
            new NativeHandleGuard(this.network.getConnectionManager())) {

      return Native.Svr3Restore(
          asyncRuntime.nativeHandle(),
          connectionManager.nativeHandle(),
          password,
          shareSet,
          auth.username,
          auth.password);
    }
  }
}
