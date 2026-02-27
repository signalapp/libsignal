//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.keytrans;

import org.signal.libsignal.net.BadRequestError;

/** Key transparency operation failed. */
public class KeyTransparencyException extends Exception implements BadRequestError {
  public KeyTransparencyException(String message) {
    super(message);
  }
}
