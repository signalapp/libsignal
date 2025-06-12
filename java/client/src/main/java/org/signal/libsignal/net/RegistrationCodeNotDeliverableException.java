//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * The attempt to send a verification code failed because an external service (e.g. the SMS
 * provider) refused to deliver the code.
 *
 * <p>When the websocket transport is in use, this corresponds to a {@code HTTP 440} response to a
 * POST request to {@code /v1/verification/session/{sessionId}/code}.
 */
public class RegistrationCodeNotDeliverableException extends RegistrationException {
  /**
   * Indicates whether the failure is permanent, as opposed to temporary.
   *
   * <p>A client may try again in response to a temporary failure after a reasonable delay.
   */
  public final boolean permanentFailure;

  /**
   * The server-provided reason for the failure.
   *
   * <p>This will likely be one of "providerUnavailable", "providerRejected", or "illegalArgument".
   */
  public final String reason;

  @CalledFromNative
  public RegistrationCodeNotDeliverableException(
      String message, String reason, boolean permanentFailure) {
    super(message);
    this.reason = reason;
    this.permanentFailure = permanentFailure;
  }
}
