//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.io.IOException

/**
 * The authenticated account did not have a username set.
 *
 * See the specific request docs for more information.
 */
public class UsernameNotSetException :
  IOException,
  BadRequestError {
  @CalledFromNative
  public constructor(message: String) : super(message) {
  }
}
