//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

/** Indicates that the local application is too old, and was rejected by the server. */
public class AppExpiredException extends ChatServiceException {
  public AppExpiredException(String message) {
    super(message);
  }
}
