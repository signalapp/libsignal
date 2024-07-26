//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

/** Indicates that an operation on the {@code ChatService} has been called before */
public class ChatServiceInactiveException extends ChatServiceException {
  public ChatServiceInactiveException(String message) {
    super(message);
  }
}
