//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * The request to send a verification code with the given transport could not be fulfilled, but may
 * succeed with a different transport.
 */
@CalledFromNative
public class RegistrationSessionSendCodeException extends RegistrationException {
  public RegistrationSessionSendCodeException(String message) {
    super(message);
  }
}
