//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.io.IOException

/**
 * The account's profile couldn't be decoded.
 *
 * See the specific request docs for more information.
 */
public class ProfileCantBeDecodedException :
  IOException,
  AuthGetProfileError {
  @CalledFromNative
  public constructor(message: String) : super(message) {
  }
}
