//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.io.IOException;
import org.signal.libsignal.internal.CalledFromNative;

/**
 * Error thrown by an unsuccessful registration request.
 *
 * <p>This is the parent class of more specific errors encountered as the result of sending a
 * registration request. It is also used for errors that don't require specialized client handling
 * or that aren't recognized error types.
 */
public class RegistrationException extends IOException {
  @CalledFromNative
  public RegistrationException(String message) {
    super(message);
  }
}
