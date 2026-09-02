//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * Thrown when the server rejects a registration request.
 *
 * <p>When the websocket transport is in use, this corresponds to a {@code HTTP 400} response to a
 * POST request to {@code /v1/registration}.
 */
public class RegisterAccountRequestRejectedException extends RegistrationException {
  @CalledFromNative
  private RegisterAccountRequestRejectedException(String message) {
    super(message);
  }
}
