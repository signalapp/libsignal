//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.receipts;

import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class ReceiptCredentialRequestContext extends ByteArray {

  public static final int SIZE = 177;

  public ReceiptCredentialRequestContext(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
    Native.ReceiptCredentialRequestContext_CheckValidContents(contents);
  }

  public ReceiptCredentialRequest getRequest() {
    byte[] newContents = Native.ReceiptCredentialRequestContext_GetRequest(contents);

    try {
      return new ReceiptCredentialRequest(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

}
