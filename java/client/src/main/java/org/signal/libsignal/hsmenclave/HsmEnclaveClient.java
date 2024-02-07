//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.hsmenclave;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

/**
 * HsmEnclaveClient provides bindings to interact with Signal's HSM-backed enclave.
 *
 * <p>Interaction with the enclave is done over a websocket, which is handled by the client. Once
 * the websocket has been initiated, the client establishes a connection in the following manner:
 *
 * <ul>
 *   <li>send HsmEnclaveClient.initialRequest()
 *   <li>receive a response and pass to HsmEnclaveClient.completeHandshake()
 * </ul>
 *
 * After a connection has been established, a client may send or receive messages. To send a
 * message, they formulate the plaintext, then pass it to HsmEnclaveClient.establishedSend() to get
 * the ciphertext message to pass along. When a message is received (as ciphertext), it is passed to
 * HsmEnclaveClient.establishedRecv(), which decrypts and verifies it, passing the plaintext back to
 * the client for processing.
 */
public class HsmEnclaveClient implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public HsmEnclaveClient(byte[] public_key, List<byte[]> code_hashes) {
    ByteArrayOutputStream concatHashes = new ByteArrayOutputStream();
    for (byte[] hash : code_hashes) {
      if (hash.length != 32) {
        throw new IllegalArgumentException("code hash length must be 32");
      }
      try {
        concatHashes.write(hash);
      } catch (IOException e) {
        throw new AssertionError("writing to ByteArrayOutputStream failed", e);
      }
    }
    this.unsafeHandle =
        filterExceptions(() -> Native.HsmEnclaveClient_New(public_key, concatHashes.toByteArray()));
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.HsmEnclaveClient_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  /** Initial request to send to HSM enclave, to begin handshake. */
  public byte[] initialRequest() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.HsmEnclaveClient_InitialRequest(guard.nativeHandle()));
    }
  }

  /** Called by client upon receipt of first message from HSM enclave, to complete handshake. */
  public void completeHandshake(byte[] handshakeResponse)
      throws EnclaveCommunicationFailureException, TrustedCodeMismatchException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      filterExceptions(
          EnclaveCommunicationFailureException.class,
          TrustedCodeMismatchException.class,
          () -> Native.HsmEnclaveClient_CompleteHandshake(guard.nativeHandle(), handshakeResponse));
    }
  }

  /** Called by client after completeHandshake has succeeded, to encrypt a message to send. */
  public byte[] establishedSend(byte[] plaintextToSend)
      throws EnclaveCommunicationFailureException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          EnclaveCommunicationFailureException.class,
          () -> Native.HsmEnclaveClient_EstablishedSend(guard.nativeHandle(), plaintextToSend));
    }
  }

  /** Called by client after completeHandshake has succeeded, to decrypt a received message. */
  public byte[] establishedRecv(byte[] receivedCiphertext)
      throws EnclaveCommunicationFailureException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          EnclaveCommunicationFailureException.class,
          () -> Native.HsmEnclaveClient_EstablishedRecv(guard.nativeHandle(), receivedCiphertext));
    }
  }
}
