//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.io.IOException

/**
 * The account already has too many TOTP keys; one must be removed before adding more.
 *
 * See the specific request docs for more information.
 */
public class TooManyTotpKeysException :
  IOException,
  GenerateTotpKeyError {
  @CalledFromNative
  public constructor(message: String) : super(message) {
  }
}
