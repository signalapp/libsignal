//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.cds2;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

import java.time.Instant;

/**
 * Cds2Client provides bindings to interact with Signal's v2 Contact Discovery Service.
 *
 * Interaction with the service is done over a websocket, which is handled by the client.  Once the websocket
 * has been initiated, the client establishes a connection in the following manner:
 *
 * <ul>
 *     <li>connect to the service websocket, read service attestation</li>
 *     <li>instantiate Cds2Client with the attestation message</li>
 *     <li>send Cds2Client.initialRequest()</li>
 *     <li>receive a response and pass to Cds2Client.completeHandshake()</li>
 * </ul>
 *
 * After a connection has been established, a client may send or receive messages.  To send a message, they
 * formulate the plaintext, then pass it to Cds2Client.establishedSend() to get the ciphertext message
 * to pass along.  When a message is received (as ciphertext), it is passed to Cds2Client.establishedRecv(),
 * which decrypts and verifies it, passing the plaintext back to the client for processing.
 *
 * A future update to Cds2Client will implement additional parts of the contact discovery protocol.
 */
public class Cds2Client implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public Cds2Client(byte[] mrenclave, byte[] attestationMsg, Instant currentInstant) throws AttestationDataException {
    this.unsafeHandle = Native.Cds2ClientState_New(mrenclave, attestationMsg, currentInstant.toEpochMilli());
  }

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.Cds2ClientState_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  /** Initial request to send to CDS 2, which begins post-attestation handshake. */
  public byte[] initialRequest() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.Cds2ClientState_InitialRequest(guard.nativeHandle());
    }
  }

  /** Called by client upon receipt of first non-attestation message from service, to complete handshake. */
  public void completeHandshake(byte[] handshakeResponse) throws Cds2CommunicationFailureException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.Cds2ClientState_CompleteHandshake(guard.nativeHandle(), handshakeResponse);
    }
  }

  /** Called by client after completeHandshake has succeeded, to encrypt a message to send. */
  public byte[] establishedSend(byte[] plaintextToSend) throws Cds2CommunicationFailureException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.Cds2ClientState_EstablishedSend(guard.nativeHandle(), plaintextToSend);
    }
  }

  /** Called by client after completeHandshake has succeeded, to decrypt a received message. */
  public byte[] establishedRecv(byte[] receivedCiphertext) throws Cds2CommunicationFailureException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.Cds2ClientState_EstablishedRecv(guard.nativeHandle(), receivedCiphertext);
    }
  }
}
