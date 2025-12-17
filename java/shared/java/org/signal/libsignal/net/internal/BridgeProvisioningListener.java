//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net.internal;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * A helper interface that represents the callback methods used by the Rust side of the bridge.
 *
 * <p>The app-facing listener API is {@link org.signal.libsignal.net.ProvisioningListener}.
 */
@CalledFromNative
public interface BridgeProvisioningListener {
  void receivedAddress(String address, long sendAckHandle);

  void receivedEnvelope(byte[] envelope, long sendAckHandle);

  // disconnectReason should always be a ChatServiceError, but it is converted to a Throwable
  //   just to be easily passed across the bridge.
  void connectionInterrupted(Throwable disconnectReason);
}
