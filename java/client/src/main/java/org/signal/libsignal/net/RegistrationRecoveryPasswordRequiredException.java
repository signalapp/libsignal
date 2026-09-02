//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * Thrown when a registration request needs a recovery password but none was provided.
 *
 * <p>An account with no phone number can only ever be recovered by the recovery password stored on
 * it, so registering one requires a non-empty {@code recoveryPassword} in the account attributes.
 * This is checked before the request is sent.
 */
public class RegistrationRecoveryPasswordRequiredException extends RegistrationException {
  @CalledFromNative
  private RegistrationRecoveryPasswordRequiredException(String message) {
    super(message);
  }
}
