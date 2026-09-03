//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.io.IOException

/**
 * The provided one-time password was not accepted for the pending TOTP key.
 *
 * See the specific request docs for more information.
 */
public class OneTimePasswordNotVerifiedException :
  IOException,
  ConfirmTotpKeyError {
  @CalledFromNative
  public constructor(message: String) : super(message) {
  }
}
