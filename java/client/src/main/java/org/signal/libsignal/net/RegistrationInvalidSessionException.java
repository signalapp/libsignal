//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * Thrown when registering with a verification session that is unverified, or that the server no
 * longer has.
 *
 * <p>The server sends the same response either way, so the caller cannot tell whether resubmitting
 * a code would help. Starting a new session always does.
 *
 * <p>Distinct from {@link RegistrationSessionIdInvalidException}, which is a session ID that could
 * not be parsed.
 *
 * <p>When the websocket transport is in use, this corresponds to a {@code HTTP 401} response to a
 * POST request to {@code /v1/registration} using session flow.
 */
public class RegistrationInvalidSessionException extends RegistrationException {
  @CalledFromNative
  private RegistrationInvalidSessionException(String message) {
    super(message);
  }
}
