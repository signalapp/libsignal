//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.receipts;

import java.nio.ByteBuffer;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

public final class ReceiptCredential extends ByteArray {

  public ReceiptCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.ReceiptCredential_CheckValidContents(contents);
  }

  public long getReceiptExpirationTime() {
    return Native.ReceiptCredential_GetReceiptExpirationTime(contents);
  }

  public long getReceiptLevel() {
    return Native.ReceiptCredential_GetReceiptLevel(contents);
  }

}
