//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.receipts;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class ReceiptCredential extends ByteArray {

  public ReceiptCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class, () -> Native.ReceiptCredential_CheckValidContents(contents));
  }

  public long getReceiptExpirationTime() {
    return Native.ReceiptCredential_GetReceiptExpirationTime(contents);
  }

  public long getReceiptLevel() {
    return Native.ReceiptCredential_GetReceiptLevel(contents);
  }
}
