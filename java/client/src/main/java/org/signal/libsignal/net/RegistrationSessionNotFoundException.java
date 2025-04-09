//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/** No session with the specified ID could be found. */
public class RegistrationSessionNotFoundException extends RegistrationException {
  @CalledFromNative
  public RegistrationSessionNotFoundException(String message) {
    super(message);
  }
}
