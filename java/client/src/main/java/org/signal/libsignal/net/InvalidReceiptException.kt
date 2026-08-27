//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.io.IOException

/**
 * A request involving a zk receipt failed because the receipt was invalid or expired.
 *
 * See the specific request docs for more information.
 */
public class InvalidReceiptException :
  IOException,
  RedeemBackupReceiptFailure {
  @CalledFromNative
  public constructor(message: String) : super(message) {
  }
}
