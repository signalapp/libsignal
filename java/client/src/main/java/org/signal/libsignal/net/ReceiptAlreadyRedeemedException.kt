//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.io.IOException

/**
 * A donation receipt was already redeemed for a badge.
 *
 * Not the same as [ReceiptCredentialException.ReceiptAlreadyIssued], which means a receipt
 * credential was already issued for the purchase.
 *
 * See the specific request docs for more information.
 */
public class ReceiptAlreadyRedeemedException :
  IOException,
  RedeemDonationReceiptFailure {
  @CalledFromNative
  public constructor(message: String) : super(message) {
  }
}
