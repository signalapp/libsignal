//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.io.IOException

/**
 * The username hash was not reserved for this account.
 *
 * See the specific request docs for more information.
 */
public class UsernameReservationNotFoundException :
  IOException,
  ConfirmUsernameError {
  @CalledFromNative
  public constructor(message: String) : super(message) {
  }
}
