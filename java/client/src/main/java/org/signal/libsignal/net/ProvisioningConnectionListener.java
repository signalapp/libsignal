//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

public interface ProvisioningConnectionListener {
  /**
   * Called at the start of the provisioning process.
   *
   * <p>{@param address} should be considered an opaque token to pass to the primary device (usually
   * via QR code).
   *
   * <p>{@param ack}'s {@code send} method can be called immediately to indicate successful delivery
   * of the address.
   */
  void onReceivedAddress(
      ProvisioningConnection chat, String address, ChatConnectionListener.ServerMessageAck ack);

  /**
   * Called once when the primary sends an "envelope" via the server (using the address from {@link
   * #onReceivedAddress(String, ChatConnectionListener.ServerMessageAck)}).
   *
   * <p>Once the server receives the {@param ack} for this message, it will close this connection.
   */
  void onReceivedEnvelope(
      ProvisioningConnection chat, byte[] envelope, ChatConnectionListener.ServerMessageAck ack);

  /**
   * Called when the client gets disconnected from the server.
   *
   * <p>This includes both deliberate disconnects as well as unexpected socket closures. In the case
   * of the former, the {@param disconnectReason} will be null.
   *
   * <p>The default implementation of this method does nothing.
   */
  default void onConnectionInterrupted(
      ProvisioningConnection chat, ChatServiceException disconnectReason) {}
}
