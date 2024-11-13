//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

/** Key transparency operation failed. */
public class KeyTransparencyException extends Exception {
  public KeyTransparencyException(String message) {
    super(message);
  }
}
