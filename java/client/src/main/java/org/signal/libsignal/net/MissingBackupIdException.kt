//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.io.IOException

/**
 * A request could not be completed because there's no backup ID registered with the server.
 *
 * See the specific request docs for more information.
 */
public class MissingBackupIdException :
  IOException,
  RedeemBackupReceiptFailure {
  @CalledFromNative
  public constructor(message: String) : super(message) {
  }
}
