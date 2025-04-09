//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net.internal;

import org.signal.libsignal.internal.CalledFromNative;

/** A helper interface that represents the callback methods used by the Rust side of the bridge. */
@CalledFromNative
public interface ConnectChatBridge {
  long getConnectionManagerUnsafeNativeHandle();
}
