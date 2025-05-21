//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * The request to send a verification code with the given transport could not be fulfilled, but may
 * succeed with a different transport.
 *
 * <p>When the websocket transport is in use, this corresponds to a {@code HTTP 418} response to a
 * POST request to {@code /v1/verification/session/{sessionId}/code}.
 */
@CalledFromNative
public class RegistrationSessionSendCodeException extends RegistrationException {
  public RegistrationSessionSendCodeException(String message) {
    super(message);
  }
}
