//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.receipts;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;

public final class ReceiptSerial extends ByteArray {

  public static final int SIZE = 16;

  public ReceiptSerial(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
  }

}
