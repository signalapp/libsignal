//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/** Unexpected response from the server. */
public class UnexpectedResponseException extends ChatServiceException {
  @CalledFromNative
  public UnexpectedResponseException(String message) {
    super(message);
  }
}
