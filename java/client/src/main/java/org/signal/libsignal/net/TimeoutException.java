//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/** Request timed out. */
public class TimeoutException extends ChatServiceException {
  @CalledFromNative
  public TimeoutException(String message) {
    super(message);
  }
}
