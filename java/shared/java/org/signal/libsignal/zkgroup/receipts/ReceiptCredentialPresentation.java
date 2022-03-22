//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.receipts;

import java.nio.ByteBuffer;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class ReceiptCredentialPresentation extends ByteArray {
  public ReceiptCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.ReceiptCredentialPresentation_CheckValidContents(contents);
  }

  public long getReceiptExpirationTime() {
    return Native.ReceiptCredentialPresentation_GetReceiptExpirationTime(contents);
  }

  public long getReceiptLevel() {
    return Native.ReceiptCredentialPresentation_GetReceiptLevel(contents);
  }

  public ReceiptSerial getReceiptSerial() {
    byte[] newContents = Native.ReceiptCredentialPresentation_GetReceiptSerial(contents);

    try {
      return new ReceiptSerial(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

}
