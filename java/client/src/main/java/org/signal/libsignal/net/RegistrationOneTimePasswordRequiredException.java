//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * Thrown when a registration request needs a one-time password but it was either missing or
 * invalid.
 *
 * <p>When the websocket transport is in use, this corresponds to a {@code HTTP 441} response to a
 * POST request to {@code /v1/registration}.
 */
public class RegistrationOneTimePasswordRequiredException extends RegistrationException {
  @CalledFromNative
  private RegistrationOneTimePasswordRequiredException(String message) {
    super(message);
  }
}
