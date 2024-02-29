//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

/** Error thrown by a network failure. */
public class NetworkException extends Exception {
  public NetworkException(String message) {
    super(message);
  }
}
