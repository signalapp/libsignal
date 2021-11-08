//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.receipts;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

public final class ReceiptCredentialResponse extends ByteArray {
  public ReceiptCredentialResponse(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.ReceiptCredentialResponse_CheckValidContents(contents);
  }
}
