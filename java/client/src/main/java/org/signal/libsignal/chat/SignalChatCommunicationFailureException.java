//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.chat;

public class SignalChatCommunicationFailureException extends Exception {
  public SignalChatCommunicationFailureException(String msg) {
    super(msg);
  }

  public SignalChatCommunicationFailureException(Throwable t) {
    super(t);
  }
}
