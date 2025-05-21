//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * The session is already verified or not in a state to request a code because requested information
 * hasn't been provided yet.
 *
 * <p>When the websocket transport is in use, this corresponds to a {@code HTTP 409} response to a
 * POST request to {@code /v1/verification/session/{sessionId}/code}.
 */
public class RegistrationSessionNotReadyException extends RegistrationException {
  @CalledFromNative
  public RegistrationSessionNotReadyException(String message) {
    super(message);
  }
}
