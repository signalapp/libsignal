//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net.internal;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * A helper interface that represents the callback methods used by the Rust side of the bridge.
 *
 * <p>The funny name is due to how the Rust side of things works, with a separate "Make" step from
 * the actual persisted "ChatListener". For Java, the act of "making" a chat listener is simply
 * persisting the local reference as a global one.
 *
 * <p>The app-facing listener API is {@link org.signal.libsignal.net.ChatListener}.
 */
@CalledFromNative
public interface MakeChatListener {
  void onIncomingMessage(byte[] envelope, long serverDeliveryTimestamp, long sendAckHandle);

  void onQueueEmpty();

  // disconnectReason should always be a ChatServiceError, but it is converted to a Throwable
  //   just to be easily passed across the bridge.
  void onConnectionInterrupted(Throwable disconnectReason);
}
