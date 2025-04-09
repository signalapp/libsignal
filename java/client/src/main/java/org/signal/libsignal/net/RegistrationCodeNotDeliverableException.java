//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * The attempt to send a verification code failed because an external service (e.g. the SMS
 * provider) refused to deliver the code.
 */
class RegistrationCodeNotDeliverableException extends RegistrationException {
  /**
   * Indicates whether the failure is permanent, as opposed to temporary.
   *
   * <p>A client may try again in response to a temporary failure after a reasonable delay.
   */
  public final boolean permanentFailure;

  /** The server-provided reason for the failure. */
  public final String reason;

  @CalledFromNative
  public RegistrationCodeNotDeliverableException(
      String message, String reason, boolean permanentFailure) {
    super(message);
    this.reason = reason;
    this.permanentFailure = permanentFailure;
  }
}
