//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.io.IOException;

/** Error thrown by an unsuccessful registration request. */
public class RegistrationException extends IOException {
  public RegistrationException(String message) {
    super(message);
  }
}
