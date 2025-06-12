//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

/**
 * Indicates that the same credentials we used to open an authenticated ChatConnection were also
 * used to open a second connection "elsewhere".
 */
public class ConnectedElsewhereException extends ChatServiceException {
  public ConnectedElsewhereException(String message) {
    super(message);
  }
}
