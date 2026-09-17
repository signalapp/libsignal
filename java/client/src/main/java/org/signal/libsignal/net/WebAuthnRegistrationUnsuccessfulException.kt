//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.io.IOException

/**
 * The WebAuthn registration ceremony's response was not verified successfully.
 *
 */
public class WebAuthnRegistrationUnsuccessfulException :
  IOException,
  FinishWebAuthnRegistrationError {
  @CalledFromNative
  public constructor(message: String) : super(message) {
  }
}
