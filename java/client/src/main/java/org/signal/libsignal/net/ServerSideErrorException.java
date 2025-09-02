//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/** Server-side error, retryable with backoff. */
public class ServerSideErrorException extends ChatServiceException {
  @CalledFromNative
  public ServerSideErrorException(String message) {
    super(message);
  }
}
