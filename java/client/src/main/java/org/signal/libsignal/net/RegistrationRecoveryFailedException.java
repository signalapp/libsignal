//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * Thrown when verification fails for registration request with a recovery password.
 *
 * <p>When the websocket transport is in use, this corresponds to a {@code HTTP 403} response to a
 * POST request to {@code /v1/registration}.
 */
public class RegistrationRecoveryFailedException extends RegistrationException {
  @CalledFromNative
  private RegistrationRecoveryFailedException(String message) {
    super(message);
  }
}
