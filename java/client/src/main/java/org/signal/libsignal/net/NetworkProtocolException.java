//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.io.IOException;

/**
 * Error thrown by a network failure on a higher level, for example failure to establish a WebSocket
 * connection.
 */
public class NetworkProtocolException extends IOException {
  public NetworkProtocolException(String message) {
    super(message);
  }
}
