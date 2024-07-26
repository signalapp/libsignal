//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

/** Error thrown by Chat Service API. */
public class ChatServiceException extends Exception {
  public ChatServiceException(String message) {
    super(message);
  }
}
