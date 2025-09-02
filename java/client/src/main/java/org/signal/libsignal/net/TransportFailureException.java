//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/** Transport-level error in Chat Service communication. */
public class TransportFailureException extends ChatServiceException {
  @CalledFromNative
  public TransportFailureException(String message) {
    super(message);
  }
}
