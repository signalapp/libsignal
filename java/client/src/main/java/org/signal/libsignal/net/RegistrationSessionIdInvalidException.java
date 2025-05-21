//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * The session ID is not valid.
 *
 * <p>Thrown when attempting to make a request, or when a response is received with a structurally
 * invalid validation session ID.
 */
public class RegistrationSessionIdInvalidException extends RegistrationException {
  @CalledFromNative
  public RegistrationSessionIdInvalidException(String message) {
    super(message);
  }
}
