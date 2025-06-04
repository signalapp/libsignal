//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.keytrans;

/** Key transparency data verification failed. */
public class VerificationFailedException extends KeyTransparencyException {
  public VerificationFailedException(String message) {
    super(message);
  }
}
