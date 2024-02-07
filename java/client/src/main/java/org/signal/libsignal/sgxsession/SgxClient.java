//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.sgxsession;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

/**
 * SgxClient provides bindings to interact with a Signal SGX service.
 *
 * <p>Interaction with the service is done over a websocket, which is handled by the client. Once
 * the websocket has been initiated, the client establishes a connection in the following manner:
 *
 * <ul>
 *   <li>connect to the service websocket, read service attestation
 *   <li>instantiate SgxClient with the attestation message
 *   <li>send SgxClient.initialRequest()
 *   <li>receive a response and pass to SgxClient.completeHandshake()
 * </ul>
 *
 * After a connection has been established, a client may send or receive messages. To send a
 * message, they formulate the plaintext, then pass it to SgxClient.establishedSend() to get the
 * ciphertext message to pass along. When a message is received (as ciphertext), it is passed to
 * SgxClient.establishedRecv(), which decrypts and verifies it, passing the plaintext back to the
 * client for processing.
 */
public class SgxClient implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  protected SgxClient(final long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.SgxClientState_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  /** Initial request to send to SGX service, which begins post-attestation handshake. */
  public byte[] initialRequest() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SgxClientState_InitialRequest(guard.nativeHandle()));
    }
  }

  /**
   * Called by client upon receipt of first non-attestation message from service, to complete
   * handshake.
   */
  public void completeHandshake(byte[] handshakeResponse) throws SgxCommunicationFailureException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      filterExceptions(
          SgxCommunicationFailureException.class,
          () -> Native.SgxClientState_CompleteHandshake(guard.nativeHandle(), handshakeResponse));
    }
  }

  /** Called by client after completeHandshake has succeeded, to encrypt a message to send. */
  public byte[] establishedSend(byte[] plaintextToSend) throws SgxCommunicationFailureException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          SgxCommunicationFailureException.class,
          () -> Native.SgxClientState_EstablishedSend(guard.nativeHandle(), plaintextToSend));
    }
  }

  /** Called by client after completeHandshake has succeeded, to decrypt a received message. */
  public byte[] establishedRecv(byte[] receivedCiphertext) throws SgxCommunicationFailureException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          SgxCommunicationFailureException.class,
          () -> Native.SgxClientState_EstablishedRecv(guard.nativeHandle(), receivedCiphertext));
    }
  }
}
