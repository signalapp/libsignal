//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.io.IOException;

/** Error thrown by Chat Service API. */
public class ChatServiceException extends IOException {
  public ChatServiceException(String message) {
    super(message);
  }

  public ChatServiceException(String message, Throwable cause) {
    super(message, cause);
  }
}
