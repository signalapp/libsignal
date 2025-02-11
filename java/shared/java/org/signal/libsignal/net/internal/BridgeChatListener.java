//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net.internal;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * A helper interface that represents the callback methods used by the Rust side of the bridge.
 *
 * <p>The app-facing listener API is {@link org.signal.libsignal.net.ChatConnectionListener}.
 */
@CalledFromNative
public interface BridgeChatListener {
  void onIncomingMessage(byte[] envelope, long serverDeliveryTimestamp, long sendAckHandle);

  void onQueueEmpty();

  // disconnectReason should always be a ChatServiceError, but it is converted to a Throwable
  //   just to be easily passed across the bridge.
  void onConnectionInterrupted(Throwable disconnectReason);
}
