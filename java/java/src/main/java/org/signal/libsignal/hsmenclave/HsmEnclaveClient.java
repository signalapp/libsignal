//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.hsmenclave;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.InvalidKeyException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * HsmEnclaveClient provides bindings to interact with Signal's HSM-backed enclave.
 *
 * Interaction with the enclave is done over a websocket, which is handled by the client.  Once the websocket
 * has been initiated, the client establishes a connection in the following manner:
 *
 * <ul>
 *     <li>send HsmEnclaveClient.initialRequest()</li>
 *     <li>receive a response and pass to HsmEnclaveClient.completeHandshake()</li>
 * </ul>
 *
 * After a connection has been established, a client may send or receive messages.  To send a message, they
 * formulate the plaintext, then pass it to HsmEnclaveClient.establishedSend() to get the ciphertext message
 * to pass along.  When a message is received (as ciphertext), it is passed to HsmEnclaveClient.establishedRecv(),
 * which decrypts and verifies it, passing the plaintext back to the client for processing.
 */
public class HsmEnclaveClient {
  private long handle;

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
    this.handle = Native.HsmEnclaveClient_New(public_key, concatHashes.toByteArray());
  }

  @Override
  protected void finalize() {
    Native.HsmEnclaveClient_Destroy(this.handle);
  }

  /** Initial request to send to HSM enclave, to begin handshake. */
  public byte[] initialRequest() {
    return Native.HsmEnclaveClient_InitialRequest(this.handle);
  }

  /** Called by client upon receipt of first message from HSM enclave, to complete handshake. */
  public void completeHandshake(byte[] handshakeResponse) {
    Native.HsmEnclaveClient_CompleteHandshake(this.handle, handshakeResponse);
  }

  /** Called by client after completeHandshake has succeeded, to encrypt a message to send. */
  public byte[] establishedSend(byte[] plaintextToSend) {
    return Native.HsmEnclaveClient_EstablishedSend(this.handle, plaintextToSend);
  }

  /** Called by client after completeHandshake has succeeded, to decrypt a received message. */
  public byte[] establishedRecv(byte[] receivedCiphertext) {
    return Native.HsmEnclaveClient_EstablishedRecv(this.handle, receivedCiphertext);
  }
}
